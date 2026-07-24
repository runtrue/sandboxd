use crate::{
    api::{self, AppState},
    auth::AuthPolicy,
    config::read_database_url,
    dispatcher::Dispatcher,
    signer::WorkOrderSigner,
    worker_auth::WorkerAuthPolicy,
};
use clap::{Args, Parser, Subcommand};
use runtrue_sandbox_placement::{
    PlacementDatabaseTls, PlacementStoreConfig, PostgresPlacementStore,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-sandbox-gateway",
    about = "Authenticated stateless sandbox placement gateway"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(ServeArgs),
    Migrate(DatabaseArgs),
}

#[derive(Debug, Args)]
struct DatabaseArgs {
    /// Owner-only file containing the exact PostgreSQL connection string.
    #[arg(long)]
    database_url_file: PathBuf,
    /// PEM CA bundle used to verify PostgreSQL.
    #[arg(long, required_unless_present = "database_insecure_local")]
    database_ca: Option<PathBuf>,
    #[arg(long, requires = "database_client_key")]
    database_client_certificate: Option<PathBuf>,
    #[arg(long, requires = "database_client_certificate")]
    database_client_key: Option<PathBuf>,
    /// Permit plaintext PostgreSQL only when every host is loopback or a Unix socket.
    #[arg(long)]
    database_insecure_local: bool,
}

#[derive(Debug, Args)]
struct ServeArgs {
    #[command(flatten)]
    database: DatabaseArgs,
    /// Owner-only JSON file mapping bearer key IDs to hashed secrets and tenant policy.
    #[arg(long)]
    auth_policy: PathBuf,
    /// Owner-only JSON file binding worker credentials to exact advertised identities.
    #[arg(long)]
    worker_auth_policy: PathBuf,
    /// Owner-only file containing the shared 32-byte work-order HMAC key.
    #[arg(long)]
    work_order_key: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// Confirm that TLS is terminated by a trusted local ingress or service mesh.
    #[arg(long)]
    allow_non_loopback_http: bool,
    #[arg(long, default_value_t = 10_000)]
    global_queue_limit: i64,
    #[arg(long, default_value_t = 1_000)]
    global_concurrency_limit: i64,
    #[arg(long, default_value_t = 100)]
    default_tenant_queue_limit: i32,
    #[arg(long, default_value_t = 10)]
    default_tenant_concurrency_limit: i32,
    #[arg(long, default_value_t = 30)]
    worker_heartbeat_timeout_seconds: u64,
    #[arg(long, default_value_t = 60)]
    lease_lifetime_seconds: u64,
    #[arg(long, default_value_t = 45)]
    work_order_lifetime_seconds: u64,
    #[arg(long, default_value_t = 40)]
    dispatch_timeout_seconds: u64,
    #[arg(long, default_value_t = 250)]
    dispatch_interval_milliseconds: u64,
    #[arg(long, default_value_t = 64)]
    dispatch_worker_scan_limit: u16,
    #[arg(long, default_value_t = 8081)]
    broker_port: u16,
}

pub(crate) async fn execute(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Migrate(database) => migrate(&database).await,
    }
}

async fn serve(args: ServeArgs) -> Result<(), String> {
    if !args.listen.ip().is_loopback() && !args.allow_non_loopback_http {
        return Err(
            "non-loopback HTTP requires --allow-non-loopback-http and trusted TLS termination"
                .to_owned(),
        );
    }
    if args.dispatch_timeout_seconds > args.work_order_lifetime_seconds
        || args.work_order_lifetime_seconds >= args.lease_lifetime_seconds
    {
        return Err(
            "dispatch timeout must not exceed work-order lifetime, which must be shorter than the lease"
                .to_owned(),
        );
    }
    let database_url = read_database_url(&args.database.database_url_file)?;
    let config = PlacementStoreConfig {
        global_queue_limit: args.global_queue_limit,
        global_concurrency_limit: args.global_concurrency_limit,
        default_tenant_queue_limit: args.default_tenant_queue_limit,
        default_tenant_concurrency_limit: args.default_tenant_concurrency_limit,
        worker_heartbeat_timeout: Duration::from_secs(args.worker_heartbeat_timeout_seconds),
        lease_lifetime: Duration::from_secs(args.lease_lifetime_seconds),
        broker_port: args.broker_port,
    };
    let store = if args.database.database_insecure_local {
        PostgresPlacementStore::connect_local_insecure(&database_url, config).await
    } else {
        PostgresPlacementStore::connect(&database_url, &database_tls(&args.database)?, config).await
    }
    .map_err(|error| error.to_string())?;
    let store = Arc::new(store);
    let signer = Arc::new(WorkOrderSigner::load(
        &args.work_order_key,
        Duration::from_secs(args.work_order_lifetime_seconds),
    )?);
    let dispatcher = Dispatcher::new(
        Arc::clone(&store),
        signer,
        Duration::from_millis(args.dispatch_interval_milliseconds),
        Duration::from_secs(args.dispatch_timeout_seconds),
        args.dispatch_worker_scan_limit,
    )?;
    let state = AppState::new(
        store,
        Arc::new(AuthPolicy::load(&args.auth_policy)?),
        Arc::new(WorkerAuthPolicy::load(&args.worker_auth_policy)?),
    );
    tokio::spawn(dispatcher.run());
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|error| format!("bind gateway listener: {error}"))?;
    axum::serve(listener, api::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| format!("serve gateway: {error}"))
}

async fn migrate(database: &DatabaseArgs) -> Result<(), String> {
    let database_url = read_database_url(&database.database_url_file)?;
    if database.database_insecure_local {
        PostgresPlacementStore::migrate_local_insecure(&database_url).await
    } else {
        PostgresPlacementStore::migrate(&database_url, &database_tls(database)?).await
    }
    .map_err(|error| error.to_string())
}

fn database_tls(database: &DatabaseArgs) -> Result<PlacementDatabaseTls, String> {
    Ok(PlacementDatabaseTls {
        ca_certificate: database
            .database_ca
            .clone()
            .ok_or_else(|| "database CA is required".to_owned())?,
        client_certificate: database.database_client_certificate.clone(),
        client_private_key: database.database_client_key.clone(),
    })
}

async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
