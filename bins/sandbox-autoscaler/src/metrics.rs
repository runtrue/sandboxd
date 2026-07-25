use axum::{
    extract::State,
    http::{header::CONTENT_TYPE, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use runtrue_sandbox_placement::{AutoscaleMetrics, PostgresPlacementStore};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;

#[derive(Clone)]
struct MetricsState {
    store: Arc<PostgresPlacementStore>,
    pool_names: Arc<Vec<String>>,
    lookback: Duration,
}

pub(crate) async fn serve(
    listener: TcpListener,
    store: Arc<PostgresPlacementStore>,
    pool_names: Vec<String>,
    lookback: Duration,
) -> Result<(), String> {
    let state = MetricsState {
        store,
        pool_names: Arc::new(pool_names),
        lookback,
    };
    let router = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(state);
    axum::serve(listener, router)
        .await
        .map_err(|error| format!("serve metrics: {error}"))
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn ready(State(state): State<MetricsState>) -> StatusCode {
    match state.store.ping().await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn metrics(State(state): State<MetricsState>) -> Response {
    match state
        .store
        .autoscale_metrics(&state.pool_names, now_unix_ms(), state.lookback)
        .await
    {
        Ok(snapshot) => (
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            )],
            render(snapshot),
        )
            .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn render(snapshot: AutoscaleMetrics) -> String {
    let mut output = String::from(
        "# HELP sandboxd_pool_queued_assignments Current durable queued assignments.\n\
         # TYPE sandboxd_pool_queued_assignments gauge\n\
         # HELP sandboxd_pool_active_leases Current durable active placement leases.\n\
         # TYPE sandboxd_pool_active_leases gauge\n\
         # HELP sandboxd_pool_clean_warm_slots Current routable clean worker slots.\n\
         # TYPE sandboxd_pool_clean_warm_slots gauge\n\
         # HELP sandboxd_pool_draining_workers Current non-routable draining workers.\n\
         # TYPE sandboxd_pool_draining_workers gauge\n\
         # HELP sandboxd_pool_desired_workers Last durable desired worker count.\n\
         # TYPE sandboxd_pool_desired_workers gauge\n\
         # HELP sandboxd_pool_utilization_ratio Leased fraction of live routable workers.\n\
         # TYPE sandboxd_pool_utilization_ratio gauge\n\
         # HELP sandboxd_pool_saturated Whether queued demand exists without a clean slot.\n\
         # TYPE sandboxd_pool_saturated gauge\n",
    );
    for pool in snapshot.pools {
        let label = prometheus_label(&pool.pool_name);
        output.push_str(&format!(
            "sandboxd_pool_queued_assignments{{pool=\"{label}\"}} {}\n\
             sandboxd_pool_active_leases{{pool=\"{label}\"}} {}\n\
             sandboxd_pool_clean_warm_slots{{pool=\"{label}\"}} {}\n\
             sandboxd_pool_draining_workers{{pool=\"{label}\"}} {}\n\
             sandboxd_pool_desired_workers{{pool=\"{label}\"}} {}\n\
             sandboxd_pool_utilization_ratio{{pool=\"{label}\"}} {:.6}\n\
             sandboxd_pool_saturated{{pool=\"{label}\"}} {}\n",
            pool.queued_assignments,
            pool.active_leases,
            pool.clean_warm_slots,
            pool.draining_workers,
            pool.desired_workers,
            pool.utilization_ratio,
            u8::from(pool.saturated),
        ));
    }
    output.push_str(
        "# HELP sandboxd_pool_latency_milliseconds Durable placement latency quantiles over the configured lookback.\n\
         # TYPE sandboxd_pool_latency_milliseconds gauge\n\
         # HELP sandboxd_pool_latency_samples Number of durable samples in the configured lookback.\n\
         # TYPE sandboxd_pool_latency_samples gauge\n",
    );
    for latency in snapshot.latencies {
        let pool = prometheus_label(&latency.pool_name);
        let phase = prometheus_label(&latency.phase);
        output.push_str(&format!(
            "sandboxd_pool_latency_samples{{pool=\"{pool}\",phase=\"{phase}\"}} {}\n",
            latency.samples
        ));
        for (quantile, value) in [
            ("0.50", latency.p50_milliseconds),
            ("0.95", latency.p95_milliseconds),
            ("0.99", latency.p99_milliseconds),
        ] {
            output.push_str(&format!(
                "sandboxd_pool_latency_milliseconds{{pool=\"{pool}\",phase=\"{phase}\",quantile=\"{quantile}\"}} {value}\n"
            ));
        }
    }
    output
}

fn prometheus_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtrue_sandbox_placement::{PoolAutoscaleMetrics, PoolLatencyMetrics};

    #[test]
    fn renders_authoritative_pool_and_quantile_metrics() {
        let rendered = render(AutoscaleMetrics {
            pools: vec![PoolAutoscaleMetrics {
                pool_name: "fixed-standard-warm".to_owned(),
                queued_assignments: 3,
                active_leases: 2,
                clean_warm_slots: 1,
                draining_workers: 0,
                desired_workers: 4,
                utilization_ratio: 2.0 / 3.0,
                saturated: false,
            }],
            latencies: vec![PoolLatencyMetrics {
                pool_name: "fixed-standard-warm".to_owned(),
                phase: "warm_wait".to_owned(),
                samples: 10,
                p50_milliseconds: 2,
                p95_milliseconds: 8,
                p99_milliseconds: 13,
            }],
        });
        assert!(
            rendered.contains("sandboxd_pool_queued_assignments{pool=\"fixed-standard-warm\"} 3")
        );
        assert!(rendered.contains("phase=\"warm_wait\",quantile=\"0.99\"} 13"));
    }
}
