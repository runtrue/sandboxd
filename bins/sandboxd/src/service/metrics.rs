use crate::{authorization::AccessContext, state::DaemonState};
use runtrue_sandbox_oci::SandboxError;
use serde_json::Value;

pub(super) fn collect(
    daemon: &DaemonState,
    context: &AccessContext,
) -> Result<Value, SandboxError> {
    if context.is_operator() {
        collect_operator(daemon)
    } else {
        collect_tenant(daemon, context)
    }
}

fn collect_operator(daemon: &DaemonState) -> Result<Value, SandboxError> {
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
        "active_operations": active.len(),
        "cached_images": images,
        "sandboxes": sandboxes.iter().filter_map(|(key, sandbox)| {
            let mut status = serde_json::to_value(sandbox.lock().ok()?.status().ok()?).ok()?;
            status["runtime_project"] = status.get("project")?.clone();
            status["project"] = Value::String(key.sandbox_id.as_str().to_owned());
            status["tenant_id"] = Value::String(key.scope.tenant_id.as_str().to_owned());
            status["workspace_id"] = Value::String(key.scope.workspace_id.as_str().to_owned());
            Some(status)
        }).collect::<Vec<_>>(),
    }))
    .map_err(|error| SandboxError::Runtime(format!("encode stats: {error}")))
}

fn collect_tenant(daemon: &DaemonState, context: &AccessContext) -> Result<Value, SandboxError> {
    let tenant_counters = daemon.tenant_counters.lock().expect("tenant counter lock");
    let sandboxes = daemon.sandboxes.lock().expect("sandbox lock");
    let counters = tenant_counters.get(context.scope());
    Ok(serde_json::json!({
        "counters": counters,
        "sandboxes": sandboxes.iter().filter_map(|(key, sandbox)| {
            if &key.scope != context.scope() {
                return None;
            }
            let mut status = serde_json::to_value(sandbox.lock().ok()?.status().ok()?).ok()?;
            status["project"] = Value::String(key.sandbox_id.as_str().to_owned());
            Some(status)
        }).collect::<Vec<_>>(),
    }))
}
