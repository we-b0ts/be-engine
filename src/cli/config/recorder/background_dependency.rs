use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Subcommand};
use traffic_e2e::{
    BackgroundDependencyFeedback, BreezeMemcachedBackgroundDependencyFeedback, E2eRunContext,
    MotanBackgroundDependencyFeedback, RedisBackgroundDependencyFeedback,
    plan_background_dependency, plan_breeze_memcached_background_dependency,
    plan_motan_background_dependency, plan_redis_background_dependency,
    resolve_single_e2e_response_rule_evidence,
};

#[derive(Debug, Args)]
pub(super) struct BackgroundDependencyArgs {
    #[arg(long)]
    name: String,
    /// Exact finalized replay case source; replay evidence is resolved internally.
    #[arg(long)]
    case_source: PathBuf,
    #[arg(long)]
    source_revision: String,
    #[arg(
        long,
        help = "Single-line source evidence proving process-level ownership and the protocol's required response relationship"
    )]
    evidence: String,
    #[command(subcommand)]
    protocol: BackgroundProtocolArgs,
}

#[derive(Debug, Subcommand)]
enum BackgroundProtocolArgs {
    /// Process-owned HTTP traffic unrelated to one case.
    Http(HttpBackgroundArgs),
    /// Process-owned Breeze-backed Memcached get traffic.
    Memcached(MemcachedBackgroundArgs),
    /// Process-owned Motan traffic unrelated to one case.
    Motan(MotanBackgroundArgs),
    /// Process-owned Redis traffic.
    Redis(RedisBackgroundArgs),
}

#[derive(Debug, Args)]
struct HttpBackgroundArgs {
    #[arg(long)]
    authority: String,
    #[arg(long)]
    method: String,
    #[arg(long)]
    path_prefix: String,
}

#[derive(Debug, Args)]
struct MemcachedBackgroundArgs {
    /// Breeze business namespace, for example `user-video`.
    #[arg(long)]
    breeze_resource: String,
    #[arg(long)]
    key_start: u64,
    #[arg(long)]
    key_end: u64,
    #[arg(long, default_value = ".")]
    key_separator: String,
    #[arg(long)]
    key_suffix: String,
    #[arg(long, default_value_t = 60_000)]
    initial_load_timeout_ms: u64,
}

#[derive(Debug, Args)]
struct MotanBackgroundArgs {
    #[arg(long)]
    group: String,
    #[arg(long)]
    interface_name: String,
    #[arg(long)]
    method_name: String,
}

#[derive(Debug, Args)]
struct RedisBackgroundArgs {
    #[command(subcommand)]
    mode: RedisBackgroundModeArgs,
}

#[derive(Debug, Subcommand)]
enum RedisBackgroundModeArgs {
    /// Process-owned Redis ZCOUNT traffic selected by key affixes.
    Zcount(RedisZcountBackgroundArgs),
    /// Process-owned Redis GET traffic selected by exact keys.
    Get(RedisExactKeyBackgroundArgs),
    /// Process-owned Redis SCARD traffic selected by exact keys.
    Scard(RedisExactKeyBackgroundArgs),
    /// Process-owned Redis HGETALL traffic selected by exact keys.
    Hgetall(RedisExactKeyBackgroundArgs),
}

#[derive(Debug, Args)]
struct RedisZcountBackgroundArgs {
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    #[arg(long)]
    key_prefix: String,
    #[arg(long)]
    key_suffix: String,
}

#[derive(Debug, Args)]
struct RedisExactKeyBackgroundArgs {
    #[arg(long = "port", required = true)]
    ports: Vec<u16>,
    #[arg(long = "key", required = true)]
    keys: Vec<String>,
    #[arg(long, default_value_t = 60_000)]
    initial_load_timeout_ms: u64,
}

pub(super) fn run(
    target_root: PathBuf,
    rules_path: PathBuf,
    args: BackgroundDependencyArgs,
    apply: bool,
) -> Result<()> {
    let BackgroundDependencyArgs {
        name,
        case_source,
        source_revision,
        evidence,
        protocol,
    } = args;
    let replay_report = resolve_single_e2e_response_rule_evidence(E2eRunContext {
        target_root,
        case_source,
        run_key: None,
    })?
    .replay;
    match protocol {
        BackgroundProtocolArgs::Http(selector) => {
            let feedback = BackgroundDependencyFeedback {
                rules_path,
                replay_report_path: replay_report,
                name,
                authority: selector.authority,
                method: selector.method,
                path_prefix: selector.path_prefix,
                source_revision,
                source_evidence: evidence,
            };
            let plan = plan_background_dependency(feedback)?;
            if apply {
                super::super::print_json(&plan.apply()?)
            } else {
                super::super::print_json(plan.report())
            }
        }
        BackgroundProtocolArgs::Memcached(selector) => {
            let feedback = BreezeMemcachedBackgroundDependencyFeedback {
                rules_path,
                replay_report_path: replay_report,
                name,
                breeze_resource: selector.breeze_resource,
                command: "get".to_string(),
                key_start: selector.key_start,
                key_end: selector.key_end,
                key_separator: selector.key_separator,
                key_suffix: selector.key_suffix,
                initial_load_timeout_ms: selector.initial_load_timeout_ms,
                source_revision,
                source_evidence: evidence,
            };
            let plan = plan_breeze_memcached_background_dependency(feedback)?;
            if apply {
                super::super::print_json(&plan.apply()?)
            } else {
                super::super::print_json(plan.report())
            }
        }
        BackgroundProtocolArgs::Motan(selector) => {
            let feedback = MotanBackgroundDependencyFeedback {
                rules_path,
                replay_report_path: replay_report,
                name,
                group: selector.group,
                interface_name: selector.interface_name,
                method_name: selector.method_name,
                source_revision,
                source_evidence: evidence,
            };
            let plan = plan_motan_background_dependency(feedback)?;
            if apply {
                super::super::print_json(&plan.apply()?)
            } else {
                super::super::print_json(plan.report())
            }
        }
        BackgroundProtocolArgs::Redis(selector) => {
            let (ports, command, keys, key_prefix, key_suffix, initial_load_timeout_ms) =
                match selector.mode {
                    RedisBackgroundModeArgs::Zcount(selector) => (
                        selector.ports,
                        "ZCOUNT".to_string(),
                        Vec::new(),
                        selector.key_prefix,
                        selector.key_suffix,
                        None,
                    ),
                    RedisBackgroundModeArgs::Get(selector) => (
                        selector.ports,
                        "GET".to_string(),
                        selector.keys,
                        String::new(),
                        String::new(),
                        Some(selector.initial_load_timeout_ms),
                    ),
                    RedisBackgroundModeArgs::Scard(selector) => (
                        selector.ports,
                        "SCARD".to_string(),
                        selector.keys,
                        String::new(),
                        String::new(),
                        Some(selector.initial_load_timeout_ms),
                    ),
                    RedisBackgroundModeArgs::Hgetall(selector) => (
                        selector.ports,
                        "HGETALL".to_string(),
                        selector.keys,
                        String::new(),
                        String::new(),
                        Some(selector.initial_load_timeout_ms),
                    ),
                };
            let feedback = RedisBackgroundDependencyFeedback {
                rules_path,
                replay_report_path: replay_report,
                name,
                ports,
                command,
                keys,
                key_patterns: Vec::new(),
                key_prefix,
                key_suffix,
                initial_load_timeout_ms,
                fields: Vec::new(),
                source_revision,
                source_evidence: evidence,
            };
            let plan = plan_redis_background_dependency(feedback)?;
            if apply {
                super::super::print_json(&plan.apply()?)
            } else {
                super::super::print_json(plan.report())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct BackgroundTestCli {
        #[command(flatten)]
        background: BackgroundDependencyArgs,
    }

    #[test]
    fn accepts_exact_motan_background_selector() {
        let parsed = BackgroundTestCli::try_parse_from([
            "test",
            "--name",
            "kunpeng-refresh",
            "--case-source",
            "/cases/run",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "MapiConfigLoader.java:init scheduled refresh",
            "motan",
            "--group",
            "kunpeng-config-rpc",
            "--interface-name",
            "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc",
            "--method-name",
            "getConfigByName",
        ])
        .unwrap();

        let BackgroundProtocolArgs::Motan(selector) = parsed.background.protocol else {
            panic!("expected Motan selector")
        };
        assert_eq!(selector.group, "kunpeng-config-rpc");
        assert_eq!(
            selector.interface_name,
            "com.weibo.api.kunpeng.rpc.ConfigItemServiceRpc"
        );
        assert_eq!(selector.method_name, "getConfigByName");
    }

    #[test]
    fn accepts_port_scoped_redis_background_selector() {
        let parsed = BackgroundTestCli::try_parse_from([
            "test",
            "--name",
            "interest-tag-mining-cache-refresh",
            "--case-source",
            "/cases/run",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "InterestTagCardServiceImpl.java:init scheduled refresh",
            "redis",
            "zcount",
            "--port",
            "20917",
            "--port",
            "20918",
            "--key-prefix",
            "1042015:",
            "--key-suffix",
            ".wtm2",
        ])
        .unwrap();

        let BackgroundProtocolArgs::Redis(selector) = parsed.background.protocol else {
            panic!("expected Redis selector")
        };
        let RedisBackgroundModeArgs::Zcount(selector) = selector.mode else {
            panic!("expected Redis ZCOUNT selector")
        };
        assert_eq!(selector.ports, [20917, 20918]);
        assert_eq!(selector.key_prefix, "1042015:");
        assert_eq!(selector.key_suffix, ".wtm2");
    }

    #[test]
    fn accepts_redis_get_exact_keys_and_u64_memcached_bounds() {
        let redis = BackgroundTestCli::try_parse_from([
            "test",
            "--name",
            "startup-cache-warm",
            "--case-source",
            "/cases/run",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "src/cache/warm.rs:init loads response-driving local state",
            "redis",
            "get",
            "--port",
            "20917",
            "--key",
            "cache:init:a",
            "--key",
            "cache:init:b",
            "--initial-load-timeout-ms",
            "30000",
        ])
        .unwrap();
        let BackgroundProtocolArgs::Redis(redis_selector) = redis.background.protocol else {
            panic!("expected Redis selector")
        };
        let RedisBackgroundModeArgs::Get(redis_selector) = redis_selector.mode else {
            panic!("expected Redis GET selector")
        };
        assert_eq!(redis_selector.keys, ["cache:init:a", "cache:init:b"]);

        let memcached = BackgroundTestCli::try_parse_from([
            "test",
            "--name",
            "profile-warm",
            "--case-source",
            "/cases/run",
            "--source-revision",
            "0123456789abcdef",
            "--evidence",
            "src/profile/cache.rs:warm reads the profile cache",
            "memcached",
            "--breeze-resource",
            "user-profile",
            "--key-start",
            "5000000000",
            "--key-end",
            "5000000000",
            "--key-suffix",
            "profile",
        ])
        .unwrap();
        let BackgroundProtocolArgs::Memcached(memcached_selector) = memcached.background.protocol
        else {
            panic!("expected Memcached selector")
        };
        assert_eq!(memcached_selector.key_start, 5_000_000_000);
        assert_eq!(memcached_selector.key_end, 5_000_000_000);
    }

    #[test]
    fn background_dependency_help_separates_protocol_selectors_and_has_no_api_flag() {
        let parent = BackgroundTestCli::try_parse_from(["test", "--help"])
            .unwrap_err()
            .to_string();
        assert!(parent.contains("http"));
        assert!(parent.contains("memcached"));
        assert!(!parent.contains("--api"));
        assert!(!parent.contains("--evidence-api"));

        let memcached = BackgroundTestCli::try_parse_from(["test", "memcached", "--help"])
            .unwrap_err()
            .to_string();
        assert!(memcached.contains("--breeze-resource"));
        assert!(!memcached.contains("--authority"));

        let zcount = BackgroundTestCli::try_parse_from(["test", "redis", "zcount", "--help"])
            .unwrap_err()
            .to_string();
        assert!(zcount.contains("--key-prefix"));
        assert!(!zcount.contains("--key <"));
        assert!(!zcount.contains("--initial-load-timeout-ms"));

        let get = BackgroundTestCli::try_parse_from(["test", "redis", "get", "--help"])
            .unwrap_err()
            .to_string();
        assert!(get.contains("--key <"));
        assert!(get.contains("--initial-load-timeout-ms"));
        assert!(!get.contains("--key-prefix"));

        for command in ["scard", "hgetall"] {
            let help = BackgroundTestCli::try_parse_from(["test", "redis", command, "--help"])
                .unwrap_err()
                .to_string();
            assert!(help.contains("--key <"));
            assert!(help.contains("--initial-load-timeout-ms"));
            assert!(!help.contains("--key-prefix"));
            assert!(!help.contains("--command"));
        }
    }
}
