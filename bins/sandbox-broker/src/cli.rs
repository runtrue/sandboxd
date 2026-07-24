use crate::broker::{self, BrokerState};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

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
}

pub(crate) async fn execute(cli: Cli) -> Result<(), String> {
    if !cli.listen.ip().is_loopback() && !cli.allow_non_loopback_http {
        return Err(
            "non-loopback HTTP requires --allow-non-loopback-http and trusted mTLS termination"
                .to_owned(),
        );
    }
    let state = BrokerState::new(
        cli.workload_socket,
        Duration::from_secs(cli.io_timeout_seconds),
    )?;
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .map_err(|error| format!("bind broker listener: {error}"))?;
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
