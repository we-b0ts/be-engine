use crate::rewrite::*;
pub fn command(status: &RewriteCommandSpec, seconds: u64) -> RewriteCommandSpec {
    action::command(
        &status.cwd,
        vec![
            "wait".into(),
            "--seconds".into(),
            seconds.clamp(1, 30).to_string(),
        ],
        Vec::new(),
    )
}
