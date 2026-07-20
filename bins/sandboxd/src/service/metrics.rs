use crate::state::DaemonState;
use runtrue_sandbox_oci::SandboxError;
use serde_json::Value;

pub(super) fn collect(daemon: &DaemonState) -> Result<Value, SandboxError> {
    let cache = daemon.cache.lock().expect("cache lock");
    let active = daemon.active.lock().expect("active lock");
    let counters = daemon.counters.lock().expect("counter lock");
    let sandboxes = daemon.sandboxes.lock().expect("sandbox lock");
    let images = cache
        .values()
        .map(|image| {
            serde_json::json!({
                "image_id": image.image_id,
                "exact_reference": image.exact_reference,
                "rootfs_digest": image.rootfs_digest,
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_value(serde_json::json!({
        "counters": &*counters,
        "active_projects": active.iter().collect::<Vec<_>>(),
        "cached_images": images,
        "sandboxes": sandboxes.values().filter_map(|sandbox| {
            sandbox.lock().ok()?.status().ok()
        }).collect::<Vec<_>>(),
    }))
    .map_err(|error| SandboxError::Runtime(format!("encode stats: {error}")))
}
