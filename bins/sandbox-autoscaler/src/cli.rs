use crate::{
    config::{read_catalog, read_exact_text},
    controller::Controller,
};
use clap::{Args, Parser};
use runtrue_sandbox_placement::{
    PlacementDatabaseTls, PlacementStoreConfig, PostgresPlacementStore,
};
use std::{path::PathBuf, sync::Arc, time::Duration};

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
    #[arg(long, default_value_t = 1_000)]
    maximum_total_workers: u32,
    #[arg(long, default_value_t = 2_000)]
    reconcile_interval_milliseconds: u64,
    #[arg(long, default_value_t = 30)]
    worker_heartbeat_timeout_seconds: u64,
    #[arg(long, default_value_t = 60)]
    lease_lifetime_seconds: u64,
    #[arg(long, default_value_t = 8081)]
    broker_port: u16,
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
    {
        return Err("autoscaler limits or namespace are invalid".to_owned());
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
    let client = kube::Client::try_default()
        .await
        .map_err(|error| format!("load Kubernetes client: {error}"))?;
    Controller::new(
        client,
        Arc::new(store),
        Arc::new(read_catalog(&cli.worker_pool_catalog)?),
        cli.namespace,
        cli.maximum_total_workers,
        Duration::from_millis(cli.reconcile_interval_milliseconds),
        cli.broker_port,
    )?
    .run()
    .await
}
