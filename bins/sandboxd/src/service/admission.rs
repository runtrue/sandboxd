use crate::state::DaemonState;
use runtrue_sandbox_gvisor::executor::ImmutableRootfs;
use runtrue_sandbox_oci::{compiler, SandboxError, TopologyLock};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

pub(super) fn admit_topology(
    daemon: &DaemonState,
    topology: &TopologyLock,
) -> Result<BTreeMap<String, ImmutableRootfs>, SandboxError> {
    compiler::verify_lock(topology)?;
    let mut result = BTreeMap::new();
    for service in topology.services.values() {
        if result.contains_key(&service.image.image_id) {
            continue;
        }
        let mut cache = daemon.cache.lock().expect("cache lock");
        let admitted = if let Some(image) = cache.get(&service.image.image_id) {
            if image.image().exact_reference != service.image.exact_reference {
                return Err(SandboxError::Lock(
                    "cached image identity conflicts with topology".to_owned(),
                ));
            }
            daemon.counters.lock().expect("counter lock").cache_hits += 1;
            Arc::clone(image)
        } else {
            let started = Instant::now();
            let image = Arc::new(daemon.image_provider.admit(&service.image)?);
            let elapsed = started.elapsed().as_millis();
            let mut counters = daemon.counters.lock().expect("counter lock");
            counters.cache_misses += 1;
            counters.admission_ms += elapsed;
            cache.insert(service.image.image_id.clone(), Arc::clone(&image));
            image
        };
        result.insert(service.image.image_id.clone(), (*admitted).clone());
    }
    Ok(result)
}
