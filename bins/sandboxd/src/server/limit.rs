use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub(super) struct ConnectionLimiter {
    active: AtomicUsize,
    maximum: usize,
}

pub(super) struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl ConnectionLimiter {
    pub(super) fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            maximum,
        })
    }

    pub(super) fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then_some(active + 1)
            })
            .ok()
            .map(|_| ConnectionPermit {
                limiter: Arc::clone(self),
            })
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub(super) fn is_idle(&self) -> bool {
        self.active.load(Ordering::Acquire) == 0
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_releases_connections() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().expect("first permit");
        assert!(limiter.try_acquire().is_none());
        assert_eq!(limiter.active(), 1);
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }
}
