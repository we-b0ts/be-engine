use anyhow::Result;
use clap::Args;
use traffic_e2e::{
    RewriteContext, RewriteEvidenceReport, RewriteWorkScope, query_rewrite_evidence,
    query_rewrite_evidence_for_scope, query_rewrite_redis_argument_for_scope,
    query_rewrite_witness_for_scope,
};

#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
#[command(group(clap::ArgGroup::new("protected_value_source").args(["witness","redis_target_event"]).multiple(false)))]
pub(super) struct EvidenceArgs {
    /// Current overview or detail-query id returned by the engine.
    #[arg(conflicts_with = "api")]
    query_id: Option<String>,
    /// Fetch this exact API implementer's current issue, identity, and evidence queries.
    #[arg(long, value_name = "PATH_OR_PATTERN")]
    api: Option<traffic_e2e::RewriteApiSelector>,
    /// Read one authenticated dependency witness in this API's current attempt.
    #[arg(long, requires_all = ["api", "pointer"])]
    witness: Option<String>,
    /// JSON pointer; MySQL also supports /sql_values/<token-index>/{value,json,field}.
    #[arg(long, requires = "protected_value_source")]
    pointer: Option<String>,
    /// Value position for a dependency operation carrying several documents.
    #[arg(long, requires = "witness")]
    value_index: Option<usize>,
    /// Select one unmatched Redis request by CASE_ID:TARGET_EVENT_INDEX.
    #[arg(long,requires_all=["api","argument_index"],conflicts_with="witness")]
    redis_target_event: Option<String>,
    /// Zero-based native argument index, excluding the Redis command name.
    #[arg(long, requires = "redis_target_event")]
    argument_index: Option<usize>,
}

impl EvidenceArgs {
    pub(super) fn query(self, context: RewriteContext) -> Result<RewriteEvidenceReport> {
        if let (Some(api), Some(event), Some(argument)) =
            (&self.api, &self.redis_target_event, self.argument_index)
        {
            let (case, index) = event.rsplit_once(':').ok_or_else(|| {
                anyhow::anyhow!("--redis-target-event requires CASE_ID:TARGET_EVENT_INDEX")
            })?;
            return query_rewrite_redis_argument_for_scope(
                context,
                &RewriteWorkScope::Api {
                    api: api.to_string(),
                },
                case,
                index.parse()?,
                argument,
                self.pointer.as_deref(),
            );
        }
        if let (Some(api), Some(witness), Some(pointer)) = (&self.api, &self.witness, &self.pointer)
        {
            return query_rewrite_witness_for_scope(
                context,
                &RewriteWorkScope::Api {
                    api: api.to_string(),
                },
                witness,
                pointer,
                self.value_index.unwrap_or(0),
            );
        }
        match (self.query_id, self.api) {
            (Some(id), None) => query_rewrite_evidence(context, &id),
            (None, Some(api)) => query_rewrite_evidence_for_scope(
                context,
                &RewriteWorkScope::Api {
                    api: api.to_string(),
                },
            ),
            _ => anyhow::bail!("select exactly one evidence query id or --api"),
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::{Cli, RewriteCommand};

    #[test]
    fn evidence_requires_exactly_one_selector() {
        for args in [
            vec!["evq-current-overview"],
            vec!["--api", "/api/tasks/*"],
            vec![
                "--api",
                "/api",
                "--redis-target-event",
                "case-1:0",
                "--argument-index",
                "0",
            ],
            vec![
                "--api",
                "/api",
                "--redis-target-event",
                "case-1:5",
                "--argument-index",
                "1",
                "--pointer",
                "/method",
            ],
            vec![
                "--api",
                "/api",
                "--witness",
                "witness-id",
                "--pointer",
                "/client_ip",
            ],
        ] {
            let cli = Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                .unwrap();
            assert!(matches!(cli.command, RewriteCommand::Evidence(_)));
        }
        for args in [
            vec![],
            vec!["evq-id", "--api", "/api"],
            vec!["--api", "not-an-api"],
            vec!["--witness", "witness-id", "--pointer", "/client_ip"],
            vec!["--api", "/api", "--witness", "witness-id"],
            vec!["--api", "/api", "--pointer", "/client_ip"],
            vec!["--api", "/api", "--value-index", "1"],
            vec!["--api", "/api", "--redis-target-event", "case-1:0"],
            vec!["--api", "/api", "--argument-index", "0"],
            vec![
                "--api",
                "/api",
                "--redis-target-event",
                "case-1:0",
                "--argument-index",
                "0",
                "--witness",
                "id",
                "--pointer",
                "/method",
            ],
        ] {
            assert!(
                Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                    .is_err()
            );
        }
    }
}
