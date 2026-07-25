use crate::{
    config::{read_catalog, read_exact_text},
    controller::Controller,
};
use clap::{Args, Parser};
use runtrue_sandbox_placement::{
    PlacementDatabaseTls, PlacementStoreConfig, PostgresPlacementStore,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-sandbox-autoscaler",
    about = "Drain-first worker-pool autoscaler"
)]
pub(crate) struct Cli {
    #[command(flatten)]
    database: DatabaseArgs,
    #[arg(long)]
    worker_pool_catalog: PathBuf,
    #[arg(long, default_value = "sandboxd-system")]
    namespace: String,
    /// Pre-allocated worker budget: the minimum of cluster and namespace quotas.
    #[arg(long)]
    maximum_total_workers: u32,
    #[arg(long, default_value_t = 2_000)]
    reconcile_interval_milliseconds: u64,
    #[arg(long, default_value_t = 30)]
    worker_heartbeat_timeout_seconds: u64,
    #[arg(long, default_value_t = 60)]
    lease_lifetime_seconds: u64,
    #[arg(long, default_value_t = 8081)]
    broker_port: u16,
    #[arg(long, default_value = "127.0.0.1:9090")]
    metrics_listen: SocketAddr,
    /// Confirm that a NetworkPolicy or trusted proxy protects non-loopback metrics.
    #[arg(long)]
    allow_non_loopback_metrics: bool,
    #[arg(long, default_value_t = 86_400)]
    metrics_lookback_seconds: u64,
}

#[derive(Debug, Args)]
struct DatabaseArgs {
    #[arg(long)]
    database_url_file: PathBuf,
    #[arg(long, required_unless_present = "database_insecure_local")]
    database_ca: Option<PathBuf>,
    #[arg(long, requires = "database_client_key")]
    database_client_certificate: Option<PathBuf>,
    #[arg(long, requires = "database_client_certificate")]
    database_client_key: Option<PathBuf>,
    #[arg(long)]
    database_insecure_local: bool,
}

pub(crate) async fn execute(cli: Cli) -> Result<(), String> {
    if cli.maximum_total_workers == 0
        || cli.maximum_total_workers > 100_000
        || cli.reconcile_interval_milliseconds < 100
        || cli.reconcile_interval_milliseconds > 60_000
        || cli.namespace.is_empty()
        || cli.namespace.len() > 63
        || cli.metrics_listen.port() == 0
        || cli.metrics_lookback_seconds == 0
        || cli.metrics_lookback_seconds > 90 * 24 * 60 * 60
    {
        return Err("autoscaler limits or namespace are invalid".to_owned());
    }
    if !cli.metrics_listen.ip().is_loopback() && !cli.allow_non_loopback_metrics {
        return Err(
            "non-loopback metrics require --allow-non-loopback-metrics and a NetworkPolicy or trusted proxy"
                .to_owned(),
        );
    }
    let database_url = read_exact_text(&cli.database.database_url_file)?;
    let store_config = PlacementStoreConfig {
        worker_heartbeat_timeout: Duration::from_secs(cli.worker_heartbeat_timeout_seconds),
        lease_lifetime: Duration::from_secs(cli.lease_lifetime_seconds),
        broker_port: cli.broker_port,
        ..PlacementStoreConfig::default()
    };
    let store = if cli.database.database_insecure_local {
        PostgresPlacementStore::connect_local_insecure(&database_url, store_config).await
    } else {
        PostgresPlacementStore::connect(
            &database_url,
            &PlacementDatabaseTls {
                ca_certificate: cli
                    .database
                    .database_ca
                    .ok_or_else(|| "database CA is required".to_owned())?,
                client_certificate: cli.database.database_client_certificate,
                client_private_key: cli.database.database_client_key,
            },
            store_config,
        )
        .await
    }
    .map_err(|error| error.to_string())?;
    let store = Arc::new(store);
    let catalog = Arc::new(read_catalog(&cli.worker_pool_catalog)?);
    let pool_names = catalog.pools.iter().map(|pool| pool.name.clone()).collect();
    let metrics_listener = tokio::net::TcpListener::bind(cli.metrics_listen)
        .await
        .map_err(|error| format!("bind metrics listener: {error}"))?;
    let client = kube::Client::try_default()
        .await
        .map_err(|error| format!("load Kubernetes client: {error}"))?;
    let controller = Controller::new(
        client,
        Arc::clone(&store),
        catalog,
        cli.namespace,
        cli.maximum_total_workers,
        Duration::from_millis(cli.reconcile_interval_milliseconds),
        cli.broker_port,
    )?;
    tokio::select! {
        result = controller.run() => result,
        result = crate::metrics::serve(
            metrics_listener,
            store,
            pool_names,
            Duration::from_secs(cli.metrics_lookback_seconds),
        ) => result,
    }
}
