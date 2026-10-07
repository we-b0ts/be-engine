//! Source-selected Redis dependency response time translation CLI.
use super::*;
use traffic_e2e::{
    RedisTimeShiftRead, RedisTimeShiftSelector, RedisTimestampFormat, RedisValueKeySelector,
    RelativeTime, RelativeTimeField,
};

#[derive(Debug, Args)]
pub(super) struct RedisTimeShiftArgs {
    #[arg(long)]
    evidence_id: String,
    #[arg(long)]
    rule_id: String,
    #[arg(long)]
    host: String,
    #[arg(long)]
    port: u16,
    #[arg(long, default_value = "HGET")]
    command: String,
    #[arg(long, default_value_t = 0)]
    database: i64,
    #[arg(long, conflicts_with_all = ["key_prefix", "key_suffix", "numeric_key_pattern", "key_numeric"])]
    key: Option<String>,
    #[arg(long, conflicts_with = "numeric_key_pattern")]
    key_prefix: Option<String>,
    #[arg(long, conflicts_with = "numeric_key_pattern")]
    key_suffix: Option<String>,
    #[arg(long, conflicts_with = "key_numeric")]
    numeric_key_pattern: Option<String>,
    #[arg(long)]
    key_numeric: bool,
    #[arg(long, conflicts_with_all = ["hash_field_prefix", "hash_field_suffix", "numeric_hash_field_pattern", "hash_field_numeric"])]
    hash_field: Option<String>,
    #[arg(long, conflicts_with = "numeric_hash_field_pattern")]
    hash_field_prefix: Option<String>,
    #[arg(long, conflicts_with = "numeric_hash_field_pattern")]
    hash_field_suffix: Option<String>,
    #[arg(long, conflicts_with = "hash_field_numeric")]
    numeric_hash_field_pattern: Option<String>,
    #[arg(long)]
    hash_field_numeric: bool,
    #[arg(long)]
    json_pointer: String,
    #[arg(long, value_enum)]
    timestamp_format: RedisTimestampFormat,
    /// Source cache/expiry computation, timestamp format and downstream consumers.
    #[arg(long)]
    source_evidence: String,
}
fn selector(
    exact: Option<String>,
    prefix: Option<String>,
    suffix: Option<String>,
    pattern: Option<String>,
    numeric: bool,
) -> Result<Option<RedisValueKeySelector>> {
    Ok(if let Some(value) = exact {
        Some(RedisValueKeySelector::Exact { value })
    } else if let Some(pattern) = pattern {
        let pattern = parse_numeric_key_pattern("time-shift", &pattern)?;
        Some(RedisValueKeySelector::Numeric {
            prefix: pattern.prefix,
            suffix: pattern.suffix,
        })
    } else if numeric {
        Some(RedisValueKeySelector::Numeric {
            prefix: prefix.unwrap_or_default(),
            suffix: suffix.unwrap_or_default(),
        })
    } else if prefix.is_some() || suffix.is_some() {
        Some(RedisValueKeySelector::Affix {
            prefix: prefix.unwrap_or_default(),
            suffix: suffix.unwrap_or_default(),
        })
    } else {
        None
    })
}

pub(super) fn options(args: RedisTimeShiftArgs) -> Result<RewriteDependencyRulePlanOptions> {
    let read = RedisTimeShiftRead {
        command: args.command.to_ascii_uppercase(),
        database: args.database,
        key: selector(
            args.key,
            args.key_prefix,
            args.key_suffix,
            args.numeric_key_pattern,
            args.key_numeric,
        )?
        .context("time-shift requires a key selector")?,
        hash_field: selector(
            args.hash_field,
            args.hash_field_prefix,
            args.hash_field_suffix,
            args.numeric_hash_field_pattern,
            args.hash_field_numeric,
        )?,
        response_json: std::collections::BTreeMap::from([(
            args.json_pointer,
            RelativeTimeField {
                time: RelativeTime::PreserveRelative,
                format: args.timestamp_format,
            },
        )]),
    };
    let selector = RedisTimeShiftSelector {
        host: args.host,
        port: args.port,
        read,
    };
    selector.validate()?;
    Ok(RewriteDependencyRulePlanOptions {
        evidence_id: args.evidence_id,
        ownership: RewriteDependencyOwnership::RequestOwned,
        name: Some(args.rule_id),
        source_evidence: Some(args.source_evidence),
        selector: RewriteDependencyRuleSelector::RedisTimeShift { selector },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: RedisTimeShiftArgs,
    }
    #[test]
    fn redis_time_shift_cli_accepts_rfc3339_get_responses() {
        let cli = Cli::try_parse_from([
            "test",
            "--evidence-id",
            "current",
            "--rule-id",
            "session-expiry",
            "--host",
            "redis.test",
            "--port",
            "6379",
            "--command",
            "GET",
            "--key-prefix",
            "vnc_session:",
            "--json-pointer",
            "/expires_at",
            "--timestamp-format",
            "rfc3339",
            "--source-evidence",
            "session.py: expires_at is a RFC3339 string compared with UTC now",
        ])
        .unwrap();
        let result = options(cli.args).unwrap();
        let RewriteDependencyRuleSelector::RedisTimeShift { selector } = result.selector else {
            panic!("expected a Redis time-shift selector");
        };
        assert_eq!(selector.read.command, "GET");
        assert_eq!(selector.read.hash_field, None);
        assert_eq!(
            selector.read.response_json["/expires_at"].format,
            RedisTimestampFormat::Rfc3339
        );
    }
    #[test]
    fn redis_time_shift_cli_patterns_and_invalid_combinations() {
        let base = [
            "test",
            "--evidence-id",
            "current",
            "--rule-id",
            "time",
            "--host",
            "redis.test",
            "--port",
            "6379",
            "--key",
            "token_v2",
            "--json-pointer",
            "/timestamp",
            "--timestamp-format",
            "unix-milliseconds",
            "--source-evidence",
            "tauth.py:67 cache expiry in milliseconds",
        ];
        for flags in [
            vec!["--hash-field", "00123"],
            vec![
                "--hash-field-prefix",
                "app:",
                "--hash-field-suffix",
                ":token",
                "--hash-field-numeric",
            ],
            vec!["--numeric-hash-field-pattern", "<id>"],
        ] {
            let cli = Cli::try_parse_from(base.iter().copied().chain(flags)).unwrap();
            let result = options(cli.args).unwrap();
            assert_eq!(result.ownership, RewriteDependencyOwnership::RequestOwned);
            assert!(matches!(
                result.selector,
                RewriteDependencyRuleSelector::RedisTimeShift { .. }
            ));
        }
        assert!(
            Cli::try_parse_from(base.iter().copied().chain([
                "--hash-field",
                "1",
                "--hash-field-numeric"
            ]))
            .is_err()
        );
        assert!(options(Cli::try_parse_from(base).unwrap().args).is_err());
    }
}
