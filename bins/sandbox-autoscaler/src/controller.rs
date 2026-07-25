use k8s_openapi::api::{apps::v1::StatefulSet, core::v1::Pod};
use kube::{
    api::{ListParams, Patch, PatchParams},
    Api, Client,
};
use runtrue_sandbox_core::{WorkerId, WorkerPool, WorkerPoolCatalog};
use runtrue_sandbox_placement::{
    PlacementStoreError, PlacementWorkerState, PostgresPlacementStore, WorkerRegistration,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::sleep;

const POOL_LABEL: &str = "runtrue.io/worker-pool";

pub(crate) struct Controller {
    stateful_sets: Api<StatefulSet>,
    pods: Api<Pod>,
    store: Arc<PostgresPlacementStore>,
    catalog: Arc<WorkerPoolCatalog>,
    maximum_total_workers: u32,
    interval: Duration,
    broker_port: u16,
}

impl Controller {
    pub(crate) fn new(
        client: Client,
        store: Arc<PostgresPlacementStore>,
        catalog: Arc<WorkerPoolCatalog>,
        namespace: String,
        maximum_total_workers: u32,
        interval: Duration,
        broker_port: u16,
    ) -> Result<Self, String> {
        catalog.validate().map_err(|error| error.to_string())?;
        if maximum_total_workers == 0
            || interval.is_zero()
            || interval > Duration::from_secs(60)
            || broker_port == 0
        {
            return Err("autoscaler controller configuration is invalid".to_owned());
        }
        Ok(Self {
            stateful_sets: Api::namespaced(client.clone(), &namespace),
            pods: Api::namespaced(client, &namespace),
            store,
            catalog,
            maximum_total_workers,
            interval,
            broker_port,
        })
    }

    pub(crate) async fn run(self) -> Result<(), String> {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|error| format!("install termination signal handler: {error}"))?;
        loop {
            if let Err(error) = self.reconcile_once().await {
                eprintln!("autoscaler reconciliation failed: {error}");
            }
            tokio::select! {
                () = sleep(self.interval) => {}
                _ = terminate.recv() => return Ok(()),
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|error| format!("wait for shutdown: {error}"))?;
                    return Ok(());
                }
            }
        }
    }

    async fn reconcile_once(&self) -> Result<(), String> {
        let mut stateful_sets = BTreeMap::new();
        let mut total_workers = 0_u32;
        for pool in &self.catalog.pools {
            let stateful_set = self
                .stateful_sets
                .get(&pool.kubernetes_stateful_set)
                .await
                .map_err(|error| {
                    format!(
                        "get StatefulSet `{}`: {error}",
                        pool.kubernetes_stateful_set
                    )
                })?;
            require_pool_identity(pool, &stateful_set)?;
            let replicas = replicas(&stateful_set)?;
            total_workers = total_workers
                .checked_add(replicas)
                .ok_or_else(|| "total worker replicas overflow".to_owned())?;
            stateful_sets.insert(pool.name.clone(), stateful_set);
        }

        for pool in &self.catalog.pools {
            let stateful_set = stateful_sets
                .get(&pool.name)
                .expect("catalog pool was fetched");
            let current = replicas(stateful_set)?;
            let available_cluster_slots = self.maximum_total_workers.saturating_sub(total_workers);
            let quota = current
                .saturating_add(available_cluster_slots)
                .min(pool.policy.maximum_workers);
            let pool_pods = self.ready_pool_pods(pool, stateful_set).await?;
            self.refresh_workers(pool, &pool_pods).await?;
            let now = now_unix_ms()?;
            let ready_workers =
                u32::try_from(pool_pods.iter().filter(|pod| pod_ready(pod)).count())
                    .map_err(|_| format!("Ready Pod count exceeds u32 for pool `{}`", pool.name))?;
            self.store
                .observe_pool_activation(&pool.name, current, ready_workers, now)
                .await
                .map_err(|error| format!("observe activation for pool `{}`: {error}", pool.name))?;
            let durable = self
                .store
                .reconcile_pool(&pool.name, current, quota, pool.policy, now)
                .await
                .map_err(|error| format!("reconcile durable pool `{}`: {error}", pool.name))?;
            if durable.decision.backpressured_assignments > 0 {
                eprintln!(
                    "{}",
                    json!({
                        "event": "worker_pool_backpressure",
                        "pool": pool.name,
                        "queued": durable.observation.queued_assignments,
                        "quota_workers": quota,
                        "backpressured_assignments": durable.decision.backpressured_assignments,
                    })
                );
            }
            if durable.decision.create_workers > 0 {
                let desired = current.saturating_add(durable.decision.create_workers);
                self.store
                    .record_scale_up(&pool.name, desired, now)
                    .await
                    .map_err(|error| {
                        format!("record scale-up for pool `{}`: {error}", pool.name)
                    })?;
                self.patch_replicas(stateful_set, desired).await?;
                total_workers = total_workers.saturating_add(durable.decision.create_workers);
            } else if durable.decision.drain_clean_workers > 0 {
                let drained = self
                    .drain_trailing_workers(
                        pool,
                        stateful_set,
                        &pool_pods,
                        durable.decision.drain_clean_workers,
                    )
                    .await?;
                if drained > 0 {
                    self.patch_replicas(stateful_set, current.saturating_sub(drained))
                        .await?;
                    total_workers = total_workers.saturating_sub(drained);
                }
            }
        }
        Ok(())
    }

    async fn ready_pool_pods(
        &self,
        pool: &WorkerPool,
        stateful_set: &StatefulSet,
    ) -> Result<Vec<Pod>, String> {
        let selector = format!("{POOL_LABEL}={}", pool.name);
        let listed = self
            .pods
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(|error| format!("list Pods for pool `{}`: {error}", pool.name))?;
        let owner_uid = stateful_set
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| "StatefulSet has no UID".to_owned())?;
        listed
            .items
            .into_iter()
            .map(|pod| {
                let owned = pod
                    .metadata
                    .owner_references
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .any(|owner| owner.controller == Some(true) && owner.uid == owner_uid);
                if !owned {
                    return Err(format!(
                        "pool label is present on Pod `{}` not owned by StatefulSet `{}`",
                        pod.metadata.name.as_deref().unwrap_or("<unknown>"),
                        pool.kubernetes_stateful_set
                    ));
                }
                Ok(pod)
            })
            .collect()
    }

    async fn refresh_workers(&self, pool: &WorkerPool, pods: &[Pod]) -> Result<(), String> {
        for pod in pods.iter().filter(|pod| pod_ready(pod)) {
            let worker_id = pod_worker_id(pod)?;
            match self
                .store
                .heartbeat_worker(&worker_id, now_unix_ms()?)
                .await
            {
                Ok(()) => continue,
                Err(PlacementStoreError::WorkerUnavailable) => {}
                Err(error) => {
                    return Err(format!("heartbeat worker `{worker_id}`: {error}"));
                }
            }
            if !self
                .store
                .worker_states(std::slice::from_ref(&worker_id))
                .await
                .map_err(|error| format!("inspect worker `{worker_id}`: {error}"))?
                .is_empty()
            {
                continue;
            }
            let pod_ip = pod
                .status
                .as_ref()
                .and_then(|status| status.pod_ip.as_deref())
                .ok_or_else(|| format!("Ready worker Pod `{worker_id}` has no IP"))?
                .parse::<IpAddr>()
                .map_err(|_| format!("Ready worker Pod `{worker_id}` has an invalid IP"))?;
            self.store
                .register_worker(
                    &WorkerRegistration {
                        worker_id: worker_id.clone(),
                        pool_name: pool.name.clone(),
                        topology: pool.placement_topology.clone(),
                        resource_shape: pool.key.resource_shape.clone(),
                        compatibility_cohort: pool.key.runtime_compatibility_cohort.clone(),
                        broker_address: SocketAddr::new(pod_ip, self.broker_port),
                        resource_ceilings: pool.resource_ceilings.clone(),
                    },
                    now_unix_ms()?,
                )
                .await
                .map_err(|error| format!("register worker `{worker_id}`: {error}"))?;
        }
        Ok(())
    }

    async fn drain_trailing_workers(
        &self,
        pool: &WorkerPool,
        stateful_set: &StatefulSet,
        pods: &[Pod],
        maximum: u32,
    ) -> Result<u32, String> {
        let current = replicas(stateful_set)?;
        let mut workers = Vec::new();
        for offset in 0..maximum.min(current) {
            let ordinal = current - offset - 1;
            let pod_name = format!("{}-{ordinal}", pool.kubernetes_stateful_set);
            let Some(pod) = pods
                .iter()
                .find(|pod| pod.metadata.name.as_deref() == Some(&pod_name))
            else {
                return Ok(0);
            };
            workers.push(pod_worker_id(pod)?);
        }
        if workers.is_empty() {
            return Ok(0);
        }
        let states = self
            .store
            .worker_states(&workers)
            .await
            .map_err(|error| format!("read trailing worker state: {error}"))?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        if states.len() != workers.len()
            || workers.iter().any(|worker| {
                !matches!(
                    states.get(worker),
                    Some(PlacementWorkerState::Clean | PlacementWorkerState::Draining)
                )
            })
        {
            return Ok(0);
        }
        let clean = workers
            .iter()
            .filter(|worker| states.get(*worker) == Some(&PlacementWorkerState::Clean))
            .cloned()
            .collect::<Vec<_>>();
        if !clean.is_empty()
            && !self
                .store
                .drain_workers_if_clean(&clean)
                .await
                .map_err(|error| format!("drain trailing workers: {error}"))?
        {
            return Ok(0);
        }
        u32::try_from(workers.len()).map_err(|_| "worker drain count overflow".to_owned())
    }

    async fn patch_replicas(&self, stateful_set: &StatefulSet, desired: u32) -> Result<(), String> {
        let name = stateful_set
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| "StatefulSet has no name".to_owned())?;
        let resource_version = stateful_set
            .metadata
            .resource_version
            .as_deref()
            .ok_or_else(|| format!("StatefulSet `{name}` has no resource version"))?;
        let desired = i32::try_from(desired)
            .map_err(|_| format!("desired replicas for `{name}` exceed i32"))?;
        self.stateful_sets
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {"resourceVersion": resource_version},
                    "spec": {"replicas": desired},
                })),
            )
            .await
            .map_err(|error| format!("scale StatefulSet `{name}`: {error}"))?;
        Ok(())
    }
}

fn require_pool_identity(pool: &WorkerPool, stateful_set: &StatefulSet) -> Result<(), String> {
    let observed = stateful_set
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(POOL_LABEL))
        .map(String::as_str);
    if observed != Some(pool.name.as_str()) {
        return Err(format!(
            "StatefulSet `{}` is not labeled for reviewed pool `{}`",
            pool.kubernetes_stateful_set, pool.name
        ));
    }
    Ok(())
}

fn replicas(stateful_set: &StatefulSet) -> Result<u32, String> {
    let value = stateful_set
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1);
    u32::try_from(value).map_err(|_| "StatefulSet has negative replicas".to_owned())
}

fn pod_ready(pod: &Pod) -> bool {
    pod.metadata.deletion_timestamp.is_none()
        && pod
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_deref())
            .unwrap_or_default()
            .iter()
            .any(|condition| condition.type_ == "Ready" && condition.status == "True")
}

fn pod_worker_id(pod: &Pod) -> Result<WorkerId, String> {
    let uid = pod
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| "worker Pod has no UID".to_owned())?;
    worker_id_from_uid(uid)
}

fn worker_id_from_uid(uid: &str) -> Result<WorkerId, String> {
    if uid.is_empty()
        || uid.len() > 48
        || !uid
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("worker Pod UID is invalid".to_owned());
    }
    WorkerId::parse(format!("worker-{uid}")).map_err(|error| error.to_string())
}

fn now_unix_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "system time exceeds u64".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_uid_becomes_one_bounded_worker_identity() {
        let worker = worker_id_from_uid("14ce3ffc-0d34-4a3a-bde4-bc495ee1ed55").expect("worker");
        assert_eq!(
            worker.as_str(),
            "worker-14ce3ffc-0d34-4a3a-bde4-bc495ee1ed55"
        );
        assert!(worker_id_from_uid("../pod").is_err());
        assert!(worker_id_from_uid(&"a".repeat(49)).is_err());
    }
}
