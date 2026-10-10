use anyhow::Result;
use clap::Args;
use traffic_e2e::{
    RewriteContext, RewriteEvidenceReport, RewriteWorkScope, query_rewrite_evidence,
    query_rewrite_evidence_for_scope,
};

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub(super) struct EvidenceArgs {
    /// Current overview or detail-query id returned by the engine.
    query_id: Option<String>,
    /// Fetch this exact API implementer's current issue, identity, and evidence queries.
    #[arg(long, value_name = "PATH_OR_PATTERN")]
    api: Option<traffic_e2e::RewriteApiSelector>,
}

impl EvidenceArgs {
    pub(super) fn query(self, context: RewriteContext) -> Result<RewriteEvidenceReport> {
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
        for args in [vec!["evq-current-overview"], vec!["--api", "/api/tasks/*"]] {
            let cli = Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                .unwrap();
            assert!(matches!(cli.command, RewriteCommand::Evidence(_)));
        }
        for args in [
            vec![],
            vec!["evq-id", "--api", "/api"],
            vec!["--api", "not-an-api"],
        ] {
            assert!(
                Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                    .is_err()
            );
        }
    }
}
