use crate::rewrite::*;
pub fn command(
    target_root: &Path,
    arguments: Vec<String>,
    required_env_names: Vec<String>,
) -> RewriteCommandSpec {
    let mut argv = Vec::with_capacity(arguments.len() + 3);
    argv.extend([
        "backend-rewrite".to_string(),
        "--target-root".to_string(),
        target_root.to_string_lossy().into_owned(),
    ]);
    argv.extend(arguments);
    RewriteCommandSpec {
        cwd: target_root.to_path_buf(),
        argv,
        required_env_names,
    }
}

pub fn status_command_for_api(target_root: &Path, api: Option<&str>) -> RewriteCommandSpec {
    let mut arguments = vec!["status".to_string()];
    if let Some(api) = api {
        arguments.extend([
            "--api".to_string(),
            super::api_selector::public_api(api).to_string(),
        ]);
    }
    command(target_root, arguments, Vec::new())
}

pub fn next_command(target_root: &Path) -> RewriteCommandSpec {
    command(target_root, vec!["next".to_string()], Vec::new())
}
