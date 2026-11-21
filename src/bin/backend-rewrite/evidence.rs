use anyhow::Result;
use clap::Args;
use traffic_e2e::{
    ImplementerEvidence, RewriteContext, RewriteEvidenceReport, RewriteWorkScope,
    query_implementer_evidence, query_rewrite_evidence, query_rewrite_redis_argument_for_scope,
    query_rewrite_witness_for_scope,
};

#[derive(Debug, Args)]
pub(super) struct EvidenceArgs {
    /// Public API path or pattern.
    #[arg(long, value_name = "PATH_OR_PATTERN")]
    api: traffic_e2e::RewriteApiSelector,
}

impl EvidenceArgs {
    pub(super) fn query(self, context: RewriteContext) -> Result<ImplementerEvidence> {
        query_implementer_evidence(
            context,
            &RewriteWorkScope::Api {
                api: self.api.to_string(),
            },
        )
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = true)]
#[command(group(clap::ArgGroup::new("protected_value_source").args(["witness","redis_target_event"]).multiple(false)))]
pub(super) struct EvidenceDetailArgs {
    /// Current overview or detail-query id returned by the engine.
    #[arg(conflicts_with = "api")]
    query_id: Option<String>,
    /// Show the current API's failures, representative evidence, and assignment.
    #[arg(
        long,
        value_name = "PATH_OR_PATTERN",
        requires = "protected_value_source"
    )]
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

impl EvidenceDetailArgs {
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
        let id = self
            .query_id
            .ok_or_else(|| anyhow::anyhow!("select an evidence detail"))?;
        query_rewrite_evidence(context, &id)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::{Cli, RewriteCommand};

    #[test]
    fn evidence_accepts_only_the_api_selector() {
        for args in [
            vec![],
            vec!["evq-current-overview"],
            vec!["--api", "not-an-api"],
        ] {
            assert!(
                Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                    .is_err()
            );
        }
        let cli =
            Cli::try_parse_from(["backend-rewrite", "evidence", "--api", "/api/tasks/*"]).unwrap();
        assert!(matches!(cli.command, RewriteCommand::Evidence(_)));
    }

    #[test]
    fn evidence_detail_requires_exactly_one_selector() {
        for args in [
            vec!["evq-current-overview"],
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
            let cli = Cli::try_parse_from(
                ["backend-rewrite", "evidence-detail"]
                    .into_iter()
                    .chain(args),
            )
            .unwrap();
            assert!(matches!(cli.command, RewriteCommand::EvidenceDetail(_)));
        }
        for args in [
            vec![],
            vec!["--api", "/api/tasks/*"],
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
                Cli::try_parse_from(
                    ["backend-rewrite", "evidence-detail"]
                        .into_iter()
                        .chain(args)
                )
                .is_err()
            );
        }
    }
}
