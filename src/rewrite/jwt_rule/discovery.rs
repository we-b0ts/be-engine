//! Safe startup-input discovery for the AI choosing a JWT signing-key source.
use super::*;

pub(super) fn query(root: &Path) -> Value {
    // Keep each input independently inspectable. A missing mount snapshot must
    // not hide JWT time evidence or a usable environment-variable source.
    let mut environment = match crate::startup::list_startup_environment(root) {
        Ok(inputs) => json!({
            "status": "available", "variables": inputs.variables,
            "overrides": inputs.overrides,
        }),
        Err(_) => json!({"status": "unavailable"}),
    };
    environment["inspect_command"] = inspect_command(root, "env");
    let mut mounts = match crate::list_startup_mounts(root) {
        Ok(inputs) => json!({
            "status": "available", "snapshot_id": inputs.snapshot_id,
            "mounts": inputs.mounts,
        }),
        Err(_) => json!({"status": "unavailable"}),
    };
    mounts["inspect_command"] = inspect_command(root, "mount");
    let profiles = match crate::e2e_run::resolve_project(root)
        .and_then(|(_, config)| policy::load(&config.replay_policy))
    {
        Ok(rules) => json!({
            "status": "available",
            "profiles": rules.jwt.profiles.into_iter().map(|(profile, settings)| json!({
                "profile": profile,
                "signing_key_ref": settings.signing_key_ref,
                "signing_key_source": settings.signing_key_source,
            })).collect::<Vec<_>>(),
        }),
        Err(_) => json!({"status": "unavailable"}),
    };
    json!({
        "environment": environment, "startup_mounts": mounts, "configured_profiles": profiles,
        "selection": "Trace the JWT key name, dotenv file path and configuration precedence in source/target code. Use --target-env NAME for an effective startup variable, or --target-key-file CONTAINER_PATH --target-key-field NAME for a dotenv file within a mount with writable=false. A directory mount may contain the file. These are available inputs, not proof of the signing-key source; plan/apply verifies the original signature. The configured profile source is persisted in verification.yaml. No target process or secret disclosure is required."
    })
}

fn inspect_command(root: &Path, kind: &str) -> Value {
    serde_json::to_value(action::command(
        root,
        vec!["startup".into(), kind.into(), "list".into()],
        Vec::new(),
    ))
    .expect("command specification is serializable")
}
