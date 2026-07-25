use crate::{CoreError, GuestProfileIdentity, ResourceCeilings};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const WORKER_POOL_CATALOG_VERSION: u32 = 1;
pub const MAXIMUM_WORKER_POOLS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFeatureTier {
    Loopback,
    UserspaceEgress,
    UserspaceIngress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageFeatureTier {
    Ephemeral,
    Directory,
    Persistent,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPoolKey {
    pub attested_root_cohort: String,
    pub resource_shape: String,
    pub guest_profile: GuestProfileIdentity,
    pub runtime_compatibility_cohort: String,
    pub network_tier: NetworkFeatureTier,
    pub storage_tier: StorageFeatureTier,
}

impl WorkerPoolKey {
    pub fn validate(&self) -> Result<(), CoreError> {
        if !valid_operator_name(&self.attested_root_cohort)
            || !valid_operator_name(&self.resource_shape)
            || !valid_operator_name(&self.runtime_compatibility_cohort)
            || self.guest_profile.canonical().len() > 63
        {
            return Err(CoreError::InvalidSpecification(
                "worker pool key is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPoolRequest {
    pub attested_root_cohort: String,
    pub resource_shape: String,
    pub guest_profile: GuestProfileIdentity,
    pub runtime_compatibility_cohort: String,
    pub network_tier: NetworkFeatureTier,
    pub storage_tier: StorageFeatureTier,
}

impl WorkerPoolRequest {
    fn as_key(&self) -> WorkerPoolKey {
        WorkerPoolKey {
            attested_root_cohort: self.attested_root_cohort.clone(),
            resource_shape: self.resource_shape.clone(),
            guest_profile: self.guest_profile.clone(),
            runtime_compatibility_cohort: self.runtime_compatibility_cohort.clone(),
            network_tier: self.network_tier,
            storage_tier: self.storage_tier,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPool {
    pub name: String,
    pub kubernetes_stateful_set: String,
    pub placement_topology: String,
    pub resource_ceilings: ResourceCeilings,
    pub key: WorkerPoolKey,
    pub policy: PoolPolicy,
    #[serde(default)]
    pub cold_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPoolCatalog {
    pub schema_version: u32,
    pub pools: Vec<WorkerPool>,
}

impl WorkerPoolCatalog {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != WORKER_POOL_CATALOG_VERSION
            || self.pools.is_empty()
            || self.pools.len() > MAXIMUM_WORKER_POOLS
        {
            return Err(CoreError::InvalidSpecification(
                "worker pool catalog version or size is invalid".to_owned(),
            ));
        }
        let mut names = BTreeSet::new();
        let mut stateful_sets = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut fallback_count = 0_usize;
        for pool in &self.pools {
            if !valid_operator_name(&pool.name)
                || !valid_operator_name(&pool.kubernetes_stateful_set)
                || !valid_operator_name(&pool.placement_topology)
                || !names.insert(&pool.name)
                || !stateful_sets.insert(&pool.kubernetes_stateful_set)
                || !keys.insert(&pool.key)
            {
                return Err(CoreError::InvalidSpecification(
                    "worker pool catalog contains duplicate or invalid identity".to_owned(),
                ));
            }
            pool.key.validate()?;
            pool.resource_ceilings.validate()?;
            pool.policy.validate()?;
            if pool.cold_fallback {
                fallback_count += 1;
            }
        }
        if fallback_count != 1 {
            return Err(CoreError::InvalidSpecification(
                "worker pool catalog must contain exactly one cold fallback".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn route(&self, request: &WorkerPoolRequest) -> Result<&WorkerPool, CoreError> {
        self.validate()?;
        let requested_key = request.as_key();
        requested_key.validate()?;
        Ok(self
            .pools
            .iter()
            .find(|pool| pool.key == requested_key)
            .or_else(|| self.pools.iter().find(|pool| pool.cold_fallback))
            .expect("validated catalog has one fallback"))
    }

    pub fn pool(&self, name: &str) -> Result<&WorkerPool, CoreError> {
        self.validate()?;
        self.pools
            .iter()
            .find(|pool| pool.name == name)
            .ok_or_else(|| {
                CoreError::InvalidSpecification(
                    "worker pool is not present in the reviewed catalog".to_owned(),
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum ServiceLevelPolicy {
    ScaleToZero,
    RetainedWarm { clean_workers: u32 },
}

impl ServiceLevelPolicy {
    pub fn apply(self, mut pool: PoolPolicy) -> Result<PoolPolicy, CoreError> {
        pool.validate()?;
        match self {
            Self::ScaleToZero => {
                pool.minimum_workers = 0;
                pool.warm_headroom = 0;
            }
            Self::RetainedWarm { clean_workers } => {
                if clean_workers == 0 || clean_workers > pool.maximum_workers {
                    return Err(CoreError::InvalidSpecification(
                        "retained warm service level is invalid".to_owned(),
                    ));
                }
                pool.minimum_workers = pool.minimum_workers.max(clean_workers);
                pool.warm_headroom = clean_workers;
            }
        }
        pool.validate()?;
        Ok(pool)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolPolicy {
    pub minimum_workers: u32,
    pub maximum_workers: u32,
    pub warm_headroom: u32,
    pub maximum_scale_up_per_reconcile: u32,
    pub maximum_scale_down_per_reconcile: u32,
    pub idle_before_scale_down_ms: u64,
}

impl PoolPolicy {
    pub fn validate(self) -> Result<(), CoreError> {
        if self.maximum_workers == 0
            || self.maximum_workers > 100_000
            || self.minimum_workers > self.maximum_workers
            || self.warm_headroom > self.maximum_workers
            || self.maximum_scale_up_per_reconcile == 0
            || self.maximum_scale_down_per_reconcile == 0
            || self.idle_before_scale_down_ms > 30 * 24 * 60 * 60 * 1_000
        {
            return Err(CoreError::InvalidSpecification(
                "worker pool autoscale policy is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolObservation {
    pub current_workers: u32,
    pub clean_workers: u32,
    pub leased_or_active_workers: u32,
    pub draining_workers: u32,
    pub queued_assignments: u32,
    pub quota_workers: u32,
    pub idle_since_unix_ms: Option<u64>,
}

impl PoolObservation {
    fn validate(self) -> Result<(), CoreError> {
        let routable = self
            .clean_workers
            .checked_add(self.leased_or_active_workers)
            .ok_or_else(|| {
                CoreError::InvalidSpecification("worker pool counters overflow".to_owned())
            })?;
        if routable > self.current_workers {
            return Err(CoreError::InvalidSpecification(
                "routable worker counters exceed current capacity".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoscaleDecision {
    pub desired_workers: u32,
    pub create_workers: u32,
    pub drain_clean_workers: u32,
    pub backpressured_assignments: u32,
}

pub fn reconcile(
    policy: PoolPolicy,
    observation: PoolObservation,
    now_unix_ms: u64,
) -> Result<AutoscaleDecision, CoreError> {
    policy.validate()?;
    observation.validate()?;

    let effective_maximum = policy.maximum_workers.min(observation.quota_workers);
    let required = observation
        .leased_or_active_workers
        .saturating_add(observation.queued_assignments)
        .saturating_add(policy.warm_headroom)
        .max(policy.minimum_workers);
    let target = required.min(effective_maximum);
    let backpressured_assignments = required.saturating_sub(effective_maximum);

    if target > observation.current_workers {
        let create_workers = target
            .saturating_sub(observation.current_workers)
            .min(policy.maximum_scale_up_per_reconcile);
        return Ok(AutoscaleDecision {
            desired_workers: observation.current_workers.saturating_add(create_workers),
            create_workers,
            drain_clean_workers: 0,
            backpressured_assignments,
        });
    }

    let idle_elapsed = observation.idle_since_unix_ms.is_some_and(|idle_since| {
        now_unix_ms.saturating_sub(idle_since) >= policy.idle_before_scale_down_ms
    });
    if target < observation.current_workers && observation.queued_assignments == 0 && idle_elapsed {
        let removable = observation
            .clean_workers
            .saturating_sub(policy.warm_headroom)
            .min(observation.current_workers.saturating_sub(target))
            .min(policy.maximum_scale_down_per_reconcile);
        return Ok(AutoscaleDecision {
            desired_workers: observation.current_workers.saturating_sub(removable),
            create_workers: 0,
            drain_clean_workers: removable,
            backpressured_assignments,
        });
    }

    Ok(AutoscaleDecision {
        desired_workers: observation.current_workers,
        create_workers: 0,
        drain_clean_workers: 0,
        backpressured_assignments,
    })
}

fn valid_operator_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PoolPolicy {
        PoolPolicy {
            minimum_workers: 0,
            maximum_workers: 100,
            warm_headroom: 2,
            maximum_scale_up_per_reconcile: 10,
            maximum_scale_down_per_reconcile: 4,
            idle_before_scale_down_ms: 60_000,
        }
    }

    fn key(resource_shape: &str) -> WorkerPoolKey {
        WorkerPoolKey {
            attested_root_cohort: "rootset-20260724".to_owned(),
            resource_shape: resource_shape.to_owned(),
            guest_profile: GuestProfileIdentity::parse("strict-v1").expect("profile"),
            runtime_compatibility_cohort: "runsc-20260714".to_owned(),
            network_tier: NetworkFeatureTier::Loopback,
            storage_tier: StorageFeatureTier::Ephemeral,
        }
    }

    fn catalog() -> WorkerPoolCatalog {
        WorkerPoolCatalog {
            schema_version: WORKER_POOL_CATALOG_VERSION,
            pools: vec![
                WorkerPool {
                    name: "standard-warm".to_owned(),
                    kubernetes_stateful_set: "sandboxd-standard-warm".to_owned(),
                    placement_topology: "fixed-v1".to_owned(),
                    resource_ceilings: ceilings(),
                    key: key("standard-v1"),
                    policy: policy(),
                    cold_fallback: false,
                },
                WorkerPool {
                    name: "reviewed-cold-fallback".to_owned(),
                    kubernetes_stateful_set: "sandboxd-cold-fallback".to_owned(),
                    placement_topology: "prepared-v1".to_owned(),
                    resource_ceilings: ceilings(),
                    key: key("fallback-v1"),
                    policy: PoolPolicy {
                        warm_headroom: 0,
                        ..policy()
                    },
                    cold_fallback: true,
                },
            ],
        }
    }

    fn ceilings() -> ResourceCeilings {
        ResourceCeilings {
            allowed_guest_profiles: vec![GuestProfileIdentity::parse("strict-v1").expect("profile")],
            maximum_services: 8,
            maximum_timeout_ms: 30_000,
            memory_bytes_per_service: 1024 * 1024 * 1024,
            cpu_per_service_millis: 1_000,
            pids_per_service: 256,
            tmpfs_bytes: 64 * 1024 * 1024,
            writable_root_bytes_per_service: 64 * 1024 * 1024,
            maximum_volumes: 8,
            maximum_volume_bytes: 512 * 1024 * 1024,
            maximum_output_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn catalog_routes_only_to_operator_reviewed_bounded_pools() {
        let catalog = catalog();
        catalog.validate().expect("catalog");
        let exact = WorkerPoolRequest {
            attested_root_cohort: "rootset-20260724".to_owned(),
            resource_shape: "standard-v1".to_owned(),
            guest_profile: GuestProfileIdentity::parse("strict-v1").expect("profile"),
            runtime_compatibility_cohort: "runsc-20260714".to_owned(),
            network_tier: NetworkFeatureTier::Loopback,
            storage_tier: StorageFeatureTier::Ephemeral,
        };
        assert_eq!(catalog.route(&exact).expect("route").name, "standard-warm");

        let mut routed_names = BTreeSet::new();
        for index in 0..10_000 {
            let mut request = exact.clone();
            request.resource_shape = format!("tenant-shape-{index}");
            routed_names.insert(catalog.route(&request).expect("fallback").name.clone());
        }
        assert_eq!(
            routed_names,
            BTreeSet::from(["reviewed-cold-fallback".to_owned()])
        );
    }

    #[test]
    fn production_pool_catalog_is_valid() {
        let catalog: WorkerPoolCatalog =
            serde_json::from_str(include_str!("../../../deploy/k3s/worker-pools.json"))
                .expect("decode production worker-pool catalog");
        catalog.validate().expect("production catalog");
    }

    #[test]
    fn catalog_rejects_duplicate_targets_and_unbounded_cardinality() {
        let mut duplicate = catalog();
        duplicate.pools[1].kubernetes_stateful_set =
            duplicate.pools[0].kubernetes_stateful_set.clone();
        assert!(duplicate.validate().is_err());

        let prototype = catalog().pools[0].clone();
        let mut oversized = catalog();
        for index in oversized.pools.len()..=MAXIMUM_WORKER_POOLS {
            let mut pool = prototype.clone();
            pool.name = format!("pool-{index}");
            pool.kubernetes_stateful_set = format!("workers-{index}");
            pool.key.resource_shape = format!("shape-{index}");
            oversized.pools.push(pool);
        }
        assert!(oversized.validate().is_err());

        let mut no_fallback = catalog();
        no_fallback.pools[1].cold_fallback = false;
        assert!(no_fallback.validate().is_err());
    }

    #[test]
    fn tenant_service_level_cannot_exceed_reviewed_pool_limit() {
        let scale_to_zero = ServiceLevelPolicy::ScaleToZero
            .apply(policy())
            .expect("scale to zero");
        assert_eq!(scale_to_zero.minimum_workers, 0);
        assert_eq!(scale_to_zero.warm_headroom, 0);

        let retained = ServiceLevelPolicy::RetainedWarm { clean_workers: 8 }
            .apply(policy())
            .expect("retained");
        assert_eq!(retained.minimum_workers, 8);
        assert_eq!(retained.warm_headroom, 8);
        assert!(ServiceLevelPolicy::RetainedWarm { clean_workers: 101 }
            .apply(policy())
            .is_err());
    }

    #[test]
    fn scale_from_zero_and_burst_growth_are_rate_limited() {
        let decision = reconcile(
            policy(),
            PoolObservation {
                current_workers: 0,
                clean_workers: 0,
                leased_or_active_workers: 0,
                draining_workers: 0,
                queued_assignments: 10_000,
                quota_workers: 80,
                idle_since_unix_ms: None,
            },
            0,
        )
        .expect("decision");
        assert_eq!(decision.desired_workers, 10);
        assert_eq!(decision.create_workers, 10);
        assert_eq!(decision.backpressured_assignments, 9_922);
    }

    #[test]
    fn scale_down_is_idle_rate_limited_and_selects_only_clean_workers() {
        let observation = PoolObservation {
            current_workers: 20,
            clean_workers: 8,
            leased_or_active_workers: 12,
            draining_workers: 0,
            queued_assignments: 0,
            quota_workers: 100,
            idle_since_unix_ms: Some(1_000),
        };
        assert_eq!(
            reconcile(policy(), observation, 60_999)
                .expect("decision")
                .drain_clean_workers,
            0
        );
        let decision = reconcile(policy(), observation, 61_000).expect("decision");
        assert_eq!(decision.drain_clean_workers, 4);
        assert_eq!(decision.desired_workers, 16);
        assert!(decision.desired_workers >= observation.leased_or_active_workers);
    }

    #[test]
    fn warm_headroom_is_replenished_and_quota_is_explicit() {
        let decision = reconcile(
            policy(),
            PoolObservation {
                current_workers: 12,
                clean_workers: 0,
                leased_or_active_workers: 12,
                draining_workers: 0,
                queued_assignments: 3,
                quota_workers: 13,
                idle_since_unix_ms: None,
            },
            0,
        )
        .expect("decision");
        assert_eq!(decision.desired_workers, 13);
        assert_eq!(decision.backpressured_assignments, 4);
    }
}
