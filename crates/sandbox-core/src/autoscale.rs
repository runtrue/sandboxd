use crate::CoreError;
use serde::{Deserialize, Serialize};

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
        let accounted = self
            .clean_workers
            .checked_add(self.leased_or_active_workers)
            .and_then(|count| count.checked_add(self.draining_workers))
            .ok_or_else(|| {
                CoreError::InvalidSpecification("worker pool counters overflow".to_owned())
            })?;
        if accounted > self.current_workers {
            return Err(CoreError::InvalidSpecification(
                "worker pool counters exceed current capacity".to_owned(),
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
