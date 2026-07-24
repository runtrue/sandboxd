use crate::broker::{self, BrokerState};
use crate::registration::RegistrationClient;
use clap::Parser;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    name = "runtrue-sandbox-broker",
    about = "Narrow signed-work-order bridge to sandboxd"
)]
pub(crate) struct Cli {
    #[arg(long, default_value = "127.0.0.1:8081")]
    listen: SocketAddr,
    /// Confirm that a trusted mTLS service mesh protects non-loopback traffic.
    #[arg(long)]
    allow_non_loopback_http: bool,
    #[arg(long, default_value = "/run/runtrue-sandboxd/workload.sock")]
    workload_socket: PathBuf,
    #[arg(long, default_value_t = 30)]
    io_timeout_seconds: u64,
    /// Gateway host:port used for authenticated registration and heartbeats.
    #[arg(
        long,
        env = "SANDBOX_GATEWAY_ADDRESS",
        requires_all = ["registration_config", "advertise_ip"]
    )]
    gateway_address: Option<String>,
    /// Owner-only worker identity, credential, capability, and ceiling document.
    #[arg(
        long,
        requires_all = ["gateway_address", "advertise_ip"]
    )]
    registration_config: Option<PathBuf>,
    /// Routable Pod IP advertised to the dispatcher.
    #[arg(
        long,
        env = "POD_IP",
        requires_all = ["gateway_address", "registration_config"]
    )]
    advertise_ip: Option<IpAddr>,
    #[arg(long, default_value_t = 10)]
    heartbeat_interval_seconds: u64,
    #[arg(long, default_value_t = 5)]
    registration_timeout_seconds: u64,
}

pub(crate) async fn execute(cli: Cli) -> Result<(), String> {
    if !cli.listen.ip().is_loopback() && !cli.allow_non_loopback_http {
        return Err(
            "non-loopback HTTP requires --allow-non-loopback-http and trusted mTLS termination"
                .to_owned(),
        );
    }
    let registration = match (
        cli.registration_config.as_deref(),
        cli.gateway_address.as_deref(),
        cli.advertise_ip,
    ) {
        (Some(config), Some(gateway), Some(advertise_ip)) => Some(RegistrationClient::load(
            config,
            gateway,
            advertise_ip,
            cli.listen.port(),
            Duration::from_secs(cli.heartbeat_interval_seconds),
            Duration::from_secs(cli.registration_timeout_seconds),
        )?),
        (None, None, None) => None,
        _ => return Err("worker registration configuration is incomplete".to_owned()),
    };
    let workload_socket = cli.workload_socket;
    let mut state = BrokerState::new(
        workload_socket.clone(),
        Duration::from_secs(cli.io_timeout_seconds),
    )?;
    if let Some(client) = &registration {
        state = state.require_registration(client.ready());
    }
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .map_err(|error| format!("bind broker listener: {error}"))?;
    if let Some(client) = registration {
        tokio::spawn(client.run_after_socket(workload_socket));
    }
    axum::serve(listener, broker::router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| format!("serve broker: {error}"))
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
