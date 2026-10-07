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
    #[arg(long, value_name = "PATH_OR_PATTERN | METHOD PATH_OR_PATTERN")]
    api: Option<traffic_e2e::RewriteApiSelector>,
    /// Fetch this process-output worker's current issue and identity.
    #[arg(long, value_name = "ID")]
    process_output: Option<String>,
}

impl EvidenceArgs {
    pub(super) fn query(self, context: RewriteContext) -> Result<RewriteEvidenceReport> {
        match (self.query_id, self.api, self.process_output) {
            (Some(id), None, None) => query_rewrite_evidence(context, &id),
            (None, Some(api), None) => query_rewrite_evidence_for_scope(
                context,
                &RewriteWorkScope::Api {
                    api: api.to_string(),
                },
            ),
            (None, None, Some(id)) => {
                query_rewrite_evidence_for_scope(context, &RewriteWorkScope::ProcessOutput { id })
            }
            _ => anyhow::bail!("select exactly one evidence query id, --api, or --process-output"),
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
            vec!["--api", "GET /api/tasks/*"],
            vec!["--api", "/api/tasks/*"],
            vec!["--process-output", "metrics"],
        ] {
            let cli = Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                .unwrap();
            assert!(matches!(cli.command, RewriteCommand::Evidence(_)));
        }
        for args in [
            vec![],
            vec!["evq-id", "--api", "GET /api"],
            vec!["evq-id", "--process-output", "metrics"],
            vec!["--api", "GET /api", "--process-output", "metrics"],
            vec!["--api", "not-an-api"],
        ] {
            assert!(
                Cli::try_parse_from(["backend-rewrite", "evidence"].into_iter().chain(args))
                    .is_err()
            );
        }
    }
}
