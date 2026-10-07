//! Source-proven Redis lock selector CLI; references are inferred from recordings.
use super::*;
#[derive(Debug, Args)]
pub(super) struct RedisLockArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    #[arg(long, conflicts_with_all = ["key_prefix", "key_suffix", "numeric_key_pattern"])]
    key: Option<String>,
    #[arg(long, conflicts_with = "numeric_key_pattern")]
    key_prefix: Option<String>,
    #[arg(long, conflicts_with = "numeric_key_pattern")]
    key_suffix: Option<String>,
    #[arg(long)]
    numeric_key_pattern: Option<String>,
    /// Source file/symbol proving random ownership tokens and conditional release.
    #[arg(long)]
    source_evidence: String,
}
pub(super) fn options(args: RedisLockArgs) -> Result<RewriteDependencyRulePlanOptions> {
    use traffic_e2e::{RedisLockSelector, RedisValueKeySelector};
    let key = if let Some(value) = args.key {
        RedisValueKeySelector::Exact { value }
    } else if let Some(pattern) = args.numeric_key_pattern {
        let pattern = super::parse_numeric_key_pattern("lock", &pattern)?;
        RedisValueKeySelector::Numeric {
            prefix: pattern.prefix,
            suffix: pattern.suffix,
        }
    } else {
        ensure!(
            args.key_prefix.is_some() || args.key_suffix.is_some(),
            "Redis lock requires --key, key affixes, or --numeric-key-pattern"
        );
        RedisValueKeySelector::Affix {
            prefix: args.key_prefix.unwrap_or_default(),
            suffix: args.key_suffix.unwrap_or_default(),
        }
    };
    Ok(RewriteDependencyRulePlanOptions {
        evidence_id: args.evidence_id,
        ownership: RewriteDependencyOwnership::RequestOwned,
        name: Some(args.rule_id),
        source_evidence: Some(args.source_evidence),
        selector: RewriteDependencyRuleSelector::RedisLock {
            selector: RedisLockSelector {
                host: args.host,
                port: args.port,
                key,
            },
        },
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: RedisDependencyRuleArgs,
    }
    #[test]
    fn lock_requires_host_port_and_key_without_script_or_uuid_flags() {
        let base = [
            "test",
            "lock",
            "--evidence-id",
            "current",
            "--rule-id",
            "locks",
            "--host",
            "redis.test",
            "--port",
            "6379",
            "--source-evidence",
            "locks.rs:acquire/release uses random ownership tokens",
        ];
        for selector in [
            ["--key", "lock:one"],
            ["--key-prefix", "lock:"],
            ["--numeric-key-pattern", "lock:<id>"],
        ] {
            let cli = Cli::try_parse_from(base.into_iter().chain(selector)).unwrap();
            assert!(matches!(
                super::super::options(cli.args).unwrap().selector,
                RewriteDependencyRuleSelector::RedisLock { .. }
            ));
        }
        assert!(super::super::options(Cli::try_parse_from(base).unwrap().args).is_err());
        assert!(
            Cli::try_parse_from(base.into_iter().chain([
                "--key",
                "lock:one",
                "--release-sha1",
                "abc"
            ]))
            .is_err()
        );
        let missing_port = base
            .into_iter()
            .filter(|arg| *arg != "--port" && *arg != "6379");
        assert!(Cli::try_parse_from(missing_port.chain(["--key", "lock:one"])).is_err());
    }
}
