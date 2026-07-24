use crate::{AssignmentEpoch, SandboxId, TenantId, WorkerId, WorkspaceId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

const FAIRNESS_QUANTUM: u32 = 100;
const MAXIMUM_LEASE_MILLIS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementIdentity {
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub sandbox_id: SandboxId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Fenced,
    Completed,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementLease {
    pub identity: PlacementIdentity,
    pub worker_id: WorkerId,
    pub epoch: AssignmentEpoch,
    pub expires_unix_ms: u64,
    pub state: LeaseState,
    pub result_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LeaseRejection {
    #[error("lease lifetime is invalid")]
    InvalidLifetime,
    #[error("an unexpired assignment already owns this sandbox")]
    ActiveConflict,
    #[error("lease identity, worker, or epoch is stale")]
    StaleFence,
    #[error("lease has expired")]
    Expired,
    #[error("result digest is invalid or conflicts with the winning result")]
    InvalidResult,
    #[error("assignment epoch overflow")]
    EpochOverflow,
}

#[derive(Debug, Default)]
pub struct LeaseBook {
    leases: BTreeMap<PlacementIdentity, PlacementLease>,
}

impl LeaseBook {
    #[must_use]
    pub fn get(&self, identity: &PlacementIdentity) -> Option<&PlacementLease> {
        self.leases.get(identity)
    }

    pub fn assign(
        &mut self,
        identity: PlacementIdentity,
        worker_id: WorkerId,
        now_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<PlacementLease, LeaseRejection> {
        if lifetime_ms == 0 || lifetime_ms > MAXIMUM_LEASE_MILLIS {
            return Err(LeaseRejection::InvalidLifetime);
        }
        let expires_unix_ms = now_unix_ms
            .checked_add(lifetime_ms)
            .ok_or(LeaseRejection::InvalidLifetime)?;
        let next_epoch = match self.leases.get(&identity) {
            Some(current)
                if current.state == LeaseState::Active && current.expires_unix_ms > now_unix_ms =>
            {
                return Err(LeaseRejection::ActiveConflict);
            }
            Some(current) => current
                .epoch
                .get()
                .checked_add(1)
                .ok_or(LeaseRejection::EpochOverflow)?,
            None => 1,
        };
        let lease = PlacementLease {
            identity: identity.clone(),
            worker_id,
            epoch: AssignmentEpoch::new(next_epoch).map_err(|_| LeaseRejection::EpochOverflow)?,
            expires_unix_ms,
            state: LeaseState::Active,
            result_digest: None,
        };
        self.leases.insert(identity, lease.clone());
        Ok(lease)
    }

    pub fn renew(
        &mut self,
        identity: &PlacementIdentity,
        worker_id: &WorkerId,
        epoch: AssignmentEpoch,
        now_unix_ms: u64,
        lifetime_ms: u64,
    ) -> Result<u64, LeaseRejection> {
        if lifetime_ms == 0 || lifetime_ms > MAXIMUM_LEASE_MILLIS {
            return Err(LeaseRejection::InvalidLifetime);
        }
        let lease = self.current_mut(identity, worker_id, epoch)?;
        if lease.expires_unix_ms <= now_unix_ms {
            lease.state = LeaseState::Fenced;
            return Err(LeaseRejection::Expired);
        }
        lease.expires_unix_ms = now_unix_ms
            .checked_add(lifetime_ms)
            .ok_or(LeaseRejection::InvalidLifetime)?;
        Ok(lease.expires_unix_ms)
    }

    pub fn complete(
        &mut self,
        identity: &PlacementIdentity,
        worker_id: &WorkerId,
        epoch: AssignmentEpoch,
        now_unix_ms: u64,
        result_digest: &str,
    ) -> Result<(), LeaseRejection> {
        if !valid_digest(result_digest) {
            return Err(LeaseRejection::InvalidResult);
        }
        let lease = self
            .leases
            .get_mut(identity)
            .ok_or(LeaseRejection::StaleFence)?;
        if lease.worker_id != *worker_id || lease.epoch != epoch {
            return Err(LeaseRejection::StaleFence);
        }
        if lease.state == LeaseState::Completed {
            return if lease.result_digest.as_deref() == Some(result_digest) {
                Ok(())
            } else {
                Err(LeaseRejection::InvalidResult)
            };
        }
        if lease.state != LeaseState::Active {
            return Err(LeaseRejection::StaleFence);
        }
        if lease.expires_unix_ms <= now_unix_ms {
            lease.state = LeaseState::Fenced;
            return Err(LeaseRejection::Expired);
        }
        lease.state = LeaseState::Completed;
        lease.result_digest = Some(result_digest.to_owned());
        Ok(())
    }

    pub fn quarantine(
        &mut self,
        identity: &PlacementIdentity,
        worker_id: &WorkerId,
        epoch: AssignmentEpoch,
    ) -> Result<(), LeaseRejection> {
        let lease = self.current_mut(identity, worker_id, epoch)?;
        lease.state = LeaseState::Quarantined;
        Ok(())
    }

    pub fn fence_expired(&mut self, now_unix_ms: u64) -> Vec<PlacementLease> {
        let mut fenced = Vec::new();
        for lease in self.leases.values_mut() {
            if lease.state == LeaseState::Active && lease.expires_unix_ms <= now_unix_ms {
                lease.state = LeaseState::Fenced;
                fenced.push(lease.clone());
            }
        }
        fenced
    }

    fn current_mut(
        &mut self,
        identity: &PlacementIdentity,
        worker_id: &WorkerId,
        epoch: AssignmentEpoch,
    ) -> Result<&mut PlacementLease, LeaseRejection> {
        let lease = self
            .leases
            .get_mut(identity)
            .ok_or(LeaseRejection::StaleFence)?;
        if lease.worker_id != *worker_id
            || lease.epoch != epoch
            || lease.state != LeaseState::Active
        {
            return Err(LeaseRejection::StaleFence);
        }
        Ok(lease)
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueLimits {
    pub global: usize,
    pub per_tenant: usize,
    pub maximum_tenants: usize,
}

impl QueueLimits {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.global > 0
            && self.global <= 1_000_000
            && self.per_tenant > 0
            && self.per_tenant <= self.global
            && self.maximum_tenants > 0
            && self.maximum_tenants <= self.global
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedWork {
    pub idempotency_key: String,
    pub tenant_id: TenantId,
    pub workspace_id: WorkspaceId,
    pub sandbox_id: SandboxId,
    pub deadline_unix_ms: u64,
}

impl QueuedWork {
    fn is_valid(&self, now_unix_ms: u64) -> bool {
        !self.idempotency_key.is_empty()
            && self.idempotency_key.len() <= 128
            && self
                .idempotency_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            && self.deadline_unix_ms > now_unix_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum QueueRejection {
    #[error("queue configuration is invalid")]
    InvalidConfiguration,
    #[error("request or deadline is invalid")]
    InvalidRequest,
    #[error("idempotency key is already queued")]
    Duplicate,
    #[error("global queue capacity is exhausted")]
    GlobalCapacity,
    #[error("tenant queue capacity is exhausted")]
    TenantCapacity,
    #[error("tenant cardinality is exhausted")]
    TenantCardinality,
    #[error("tenant weight must be between 1 and 100")]
    InvalidWeight,
}

#[derive(Debug)]
struct TenantQueue {
    weight: u8,
    deficit: u32,
    work: VecDeque<QueuedWork>,
}

#[derive(Debug)]
pub struct BoundedFairQueue {
    limits: QueueLimits,
    total: usize,
    queued_keys: BTreeSet<String>,
    tenants: BTreeMap<TenantId, TenantQueue>,
    schedule: VecDeque<TenantId>,
}

impl BoundedFairQueue {
    pub fn new(limits: QueueLimits) -> Result<Self, QueueRejection> {
        if !limits.is_valid() {
            return Err(QueueRejection::InvalidConfiguration);
        }
        Ok(Self {
            limits,
            total: 0,
            queued_keys: BTreeSet::new(),
            tenants: BTreeMap::new(),
            schedule: VecDeque::new(),
        })
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.total
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn set_tenant_weight(
        &mut self,
        tenant_id: &TenantId,
        weight: u8,
    ) -> Result<(), QueueRejection> {
        if !(1..=100).contains(&weight) {
            return Err(QueueRejection::InvalidWeight);
        }
        if let Some(queue) = self.tenants.get_mut(tenant_id) {
            queue.weight = weight;
        } else {
            if self.tenants.len() >= self.limits.maximum_tenants {
                return Err(QueueRejection::TenantCardinality);
            }
            self.tenants.insert(
                tenant_id.clone(),
                TenantQueue {
                    weight,
                    deficit: 0,
                    work: VecDeque::new(),
                },
            );
        }
        Ok(())
    }

    pub fn enqueue(&mut self, work: QueuedWork, now_unix_ms: u64) -> Result<(), QueueRejection> {
        if !work.is_valid(now_unix_ms) {
            return Err(QueueRejection::InvalidRequest);
        }
        if self.queued_keys.contains(&work.idempotency_key) {
            return Err(QueueRejection::Duplicate);
        }
        if self.total >= self.limits.global {
            return Err(QueueRejection::GlobalCapacity);
        }
        if !self.tenants.contains_key(&work.tenant_id) {
            self.set_tenant_weight(&work.tenant_id, 1)?;
        }
        let queue = self
            .tenants
            .get_mut(&work.tenant_id)
            .expect("tenant queue exists");
        if queue.work.len() >= self.limits.per_tenant {
            return Err(QueueRejection::TenantCapacity);
        }
        if queue.work.is_empty() {
            self.schedule.push_back(work.tenant_id.clone());
        }
        self.queued_keys.insert(work.idempotency_key.clone());
        queue.work.push_back(work);
        self.total += 1;
        Ok(())
    }

    pub fn cancel(&mut self, idempotency_key: &str) -> Option<QueuedWork> {
        if !self.queued_keys.contains(idempotency_key) {
            return None;
        }
        let tenant_id = self.tenants.iter().find_map(|(tenant_id, queue)| {
            queue
                .work
                .iter()
                .any(|work| work.idempotency_key == idempotency_key)
                .then(|| tenant_id.clone())
        })?;
        let queue = self.tenants.get_mut(&tenant_id)?;
        let position = queue
            .work
            .iter()
            .position(|work| work.idempotency_key == idempotency_key)?;
        let removed = queue.work.remove(position)?;
        self.queued_keys.remove(idempotency_key);
        self.total -= 1;
        self.remove_empty_tenant(&tenant_id);
        Some(removed)
    }

    pub fn dequeue(&mut self, now_unix_ms: u64) -> Option<QueuedWork> {
        self.expire(now_unix_ms);
        let attempts = self
            .schedule
            .len()
            .saturating_mul(FAIRNESS_QUANTUM as usize);
        for _ in 0..attempts {
            let tenant_id = self.schedule.pop_front()?;
            let queue = self
                .tenants
                .get_mut(&tenant_id)
                .expect("scheduled tenant exists");
            queue.deficit = queue
                .deficit
                .saturating_add(u32::from(queue.weight))
                .min(FAIRNESS_QUANTUM * 2);
            if queue.deficit < FAIRNESS_QUANTUM {
                self.schedule.push_back(tenant_id);
                continue;
            }
            queue.deficit -= FAIRNESS_QUANTUM;
            let work = queue.work.pop_front().expect("scheduled queue is nonempty");
            self.queued_keys.remove(&work.idempotency_key);
            self.total -= 1;
            if queue.work.is_empty() {
                self.tenants.remove(&tenant_id);
            } else if queue.deficit >= FAIRNESS_QUANTUM {
                self.schedule.push_front(tenant_id);
            } else {
                self.schedule.push_back(tenant_id);
            }
            return Some(work);
        }
        None
    }

    pub fn expire(&mut self, now_unix_ms: u64) -> Vec<QueuedWork> {
        let tenant_ids = self.tenants.keys().cloned().collect::<Vec<_>>();
        let mut expired = Vec::new();
        for tenant_id in tenant_ids {
            let queue = self.tenants.get_mut(&tenant_id).expect("tenant exists");
            let mut retained = VecDeque::with_capacity(queue.work.len());
            while let Some(work) = queue.work.pop_front() {
                if work.deadline_unix_ms <= now_unix_ms {
                    self.queued_keys.remove(&work.idempotency_key);
                    self.total -= 1;
                    expired.push(work);
                } else {
                    retained.push_back(work);
                }
            }
            queue.work = retained;
            self.remove_empty_tenant(&tenant_id);
        }
        expired
    }

    fn remove_empty_tenant(&mut self, tenant_id: &TenantId) {
        if self
            .tenants
            .get(tenant_id)
            .is_some_and(|queue| queue.work.is_empty())
        {
            self.tenants.remove(tenant_id);
            self.schedule.retain(|scheduled| scheduled != tenant_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(tenant: &str, sequence: usize, deadline: u64) -> QueuedWork {
        QueuedWork {
            idempotency_key: format!("{tenant}-{sequence}"),
            tenant_id: TenantId::parse(tenant).expect("tenant"),
            workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
            sandbox_id: SandboxId::parse(format!("sandbox-{sequence}")).expect("sandbox"),
            deadline_unix_ms: deadline,
        }
    }

    fn identity() -> PlacementIdentity {
        PlacementIdentity {
            tenant_id: TenantId::parse("tenant-a").expect("tenant"),
            workspace_id: WorkspaceId::parse("team-a").expect("workspace"),
            sandbox_id: SandboxId::parse("sandbox-a").expect("sandbox"),
        }
    }

    #[test]
    fn stale_worker_cannot_renew_or_publish_after_reassignment() {
        let mut leases = LeaseBook::default();
        let source = WorkerId::parse("worker-a").expect("worker");
        let destination = WorkerId::parse("worker-b").expect("worker");
        let first = leases
            .assign(identity(), source.clone(), 100, 10)
            .expect("source lease");
        assert_eq!(leases.fence_expired(110).len(), 1);
        let second = leases
            .assign(identity(), destination.clone(), 110, 10)
            .expect("destination lease");
        assert!(second.epoch > first.epoch);
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            leases.complete(&identity(), &source, first.epoch, 111, &digest),
            Err(LeaseRejection::StaleFence)
        );
        leases
            .complete(&identity(), &destination, second.epoch, 111, &digest)
            .expect("winning completion");
        leases
            .complete(&identity(), &destination, second.epoch, 111, &digest)
            .expect("idempotent completion");
    }

    #[test]
    fn live_lease_conflicts_and_expiration_fails_closed() {
        let mut leases = LeaseBook::default();
        let worker = WorkerId::parse("worker-a").expect("worker");
        let lease = leases
            .assign(identity(), worker.clone(), 100, 10)
            .expect("lease");
        assert_eq!(
            leases.assign(identity(), worker.clone(), 101, 10),
            Err(LeaseRejection::ActiveConflict)
        );
        assert_eq!(
            leases.renew(&identity(), &worker, lease.epoch, 110, 10),
            Err(LeaseRejection::Expired)
        );
        assert_eq!(
            leases.get(&identity()).expect("lease").state,
            LeaseState::Fenced
        );
    }

    #[test]
    fn burst_is_bounded_globally_and_per_tenant() {
        let mut queue = BoundedFairQueue::new(QueueLimits {
            global: 10,
            per_tenant: 6,
            maximum_tenants: 4,
        })
        .expect("queue");
        for sequence in 0..6 {
            queue
                .enqueue(work("tenant-a", sequence, 10), 0)
                .expect("tenant capacity");
        }
        assert_eq!(
            queue.enqueue(work("tenant-a", 7, 10), 0),
            Err(QueueRejection::TenantCapacity)
        );
        for sequence in 0..4 {
            queue
                .enqueue(work("tenant-b", sequence, 10), 0)
                .expect("global capacity");
        }
        for sequence in 0..1_000 {
            assert_eq!(
                queue.enqueue(work("tenant-c", sequence, 10), 0),
                Err(QueueRejection::GlobalCapacity)
            );
        }
        assert_eq!(queue.len(), 10);
    }

    #[test]
    fn operator_weighting_is_fair_and_low_weight_tenant_is_not_starved() {
        let mut queue = BoundedFairQueue::new(QueueLimits {
            global: 400,
            per_tenant: 200,
            maximum_tenants: 2,
        })
        .expect("queue");
        let high = TenantId::parse("tenant-high").expect("tenant");
        let low = TenantId::parse("tenant-low").expect("tenant");
        queue.set_tenant_weight(&high, 100).expect("weight");
        queue.set_tenant_weight(&low, 10).expect("weight");
        for sequence in 0..100 {
            queue
                .enqueue(work("tenant-high", sequence, 100), 0)
                .expect("enqueue");
            queue
                .enqueue(work("tenant-low", sequence, 100), 0)
                .expect("enqueue");
        }
        let first_twenty = (0..20)
            .map(|_| queue.dequeue(0).expect("work").tenant_id)
            .collect::<Vec<_>>();
        let high_count = first_twenty
            .iter()
            .filter(|tenant| **tenant == high)
            .count();
        let low_count = first_twenty.iter().filter(|tenant| **tenant == low).count();
        assert!(high_count > low_count);
        assert!(low_count > 0);
    }

    #[test]
    fn deadline_cancellation_and_idempotency_release_capacity() {
        let mut queue = BoundedFairQueue::new(QueueLimits {
            global: 2,
            per_tenant: 2,
            maximum_tenants: 1,
        })
        .expect("queue");
        queue.enqueue(work("tenant-a", 1, 5), 0).expect("enqueue");
        assert_eq!(
            queue.enqueue(work("tenant-a", 1, 5), 0),
            Err(QueueRejection::Duplicate)
        );
        queue.enqueue(work("tenant-a", 2, 10), 0).expect("enqueue");
        assert_eq!(queue.expire(5).len(), 1);
        assert!(queue.cancel("tenant-a-2").is_some());
        assert!(queue.is_empty());
    }
}
