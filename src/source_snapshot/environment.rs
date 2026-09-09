pub(super) fn is_target_environment_name(name: &str) -> bool {
    let runtime_owned = [
        "HOSTNAME", "PATH", "HOME", "PWD", "OLDPWD", "SHLVL", "_", "TERM",
    ];
    let mut bytes = name.bytes();
    !runtime_owned.contains(&name)
        && !name.to_ascii_uppercase().starts_with("TRAFFIC_E2E_")
        && bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}
