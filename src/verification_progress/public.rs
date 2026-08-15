use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::{
    ApiCounts, ApiTotals, LatestCounts, LatestRun, PROGRESS_VERSION, ProgressApi, ProgressReport,
    ProgressTotals, SuccessCounts, SuccessStreak, VerificationStage,
};

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    version: u8,
    updated_at: String,
    totals: PublicProgressTotals,
    latest_run: Option<PublicLatestRun>,
    apis: BTreeMap<String, PublicProgressApi>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicProgressTotals {
    runs: PublicSuccessCounts,
    cases: PublicSuccessCounts,
    apis: PublicApiCoverage,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicSuccessCounts {
    executed: u64,
    passed: u64,
    success_streak: u64,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicApiCoverage {
    covered: u64,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicLatestRun {
    passed: Option<bool>,
    apis: u64,
    cases: u64,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicProgressApi {
    runs: PublicSuccessCounts,
    cases: PublicSuccessCounts,
}

impl Snapshot {
    pub(super) fn from_report(report: &ProgressReport) -> Self {
        Self {
            version: PROGRESS_VERSION,
            updated_at: report.updated_at.clone(),
            totals: PublicProgressTotals {
                runs: PublicSuccessCounts {
                    executed: report.totals.runs.executed,
                    passed: report.totals.runs.passed,
                    success_streak: report.success_streak.runs,
                },
                cases: PublicSuccessCounts {
                    executed: report.totals.cases.executed,
                    passed: report.totals.cases.passed,
                    success_streak: report.success_streak.cases,
                },
                apis: PublicApiCoverage {
                    covered: report.totals.apis.total,
                },
            },
            latest_run: report.latest_run.as_ref().map(|latest| PublicLatestRun {
                passed: latest.finalized.then_some(latest.passed),
                apis: latest.apis.executed,
                cases: latest.cases.executed,
            }),
            apis: report
                .apis
                .iter()
                .map(|(api, progress)| {
                    (
                        api.clone(),
                        PublicProgressApi {
                            runs: PublicSuccessCounts {
                                executed: progress.totals.runs.executed,
                                passed: progress.totals.runs.passed,
                                success_streak: progress.success_streak.runs,
                            },
                            cases: PublicSuccessCounts {
                                executed: progress.totals.cases.executed,
                                passed: progress.totals.cases.passed,
                                success_streak: progress.success_streak.cases,
                            },
                        },
                    )
                })
                .collect(),
        }
    }

    fn into_report(self, stage: VerificationStage) -> ProgressReport {
        let success_streak = SuccessStreak {
            runs: self.totals.runs.success_streak,
            cases: self.totals.cases.success_streak,
        };
        let latest_run = self.latest_run.map(|latest| LatestRun {
            key: format!("public-v3:{}", self.updated_at),
            evidence_fingerprint: format!("public-v3:{}", self.updated_at),
            number: self.totals.runs.executed,
            finalized: latest.passed.is_some(),
            passed: latest.passed.unwrap_or(false),
            cases: LatestCounts {
                executed: latest.cases,
                passed: u64::from(latest.passed == Some(true)).saturating_mul(latest.cases),
            },
            apis: LatestCounts {
                executed: latest.apis,
                passed: u64::from(latest.passed == Some(true)).saturating_mul(latest.apis),
            },
            scope: Vec::new(),
        });
        ProgressReport {
            version: PROGRESS_VERSION,
            stage,
            updated_at: self.updated_at,
            totals: ProgressTotals {
                runs: SuccessCounts {
                    executed: self.totals.runs.executed,
                    passed: self.totals.runs.passed,
                },
                cases: SuccessCounts {
                    executed: self.totals.cases.executed,
                    passed: self.totals.cases.passed,
                },
                apis: ApiCounts {
                    total: self.totals.apis.covered,
                },
            },
            success_streak,
            latest_run,
            counted_runs: BTreeMap::new(),
            counted_observations: BTreeMap::new(),
            observation_baseline: None,
            apis: self
                .apis
                .into_iter()
                .map(|(api, progress)| {
                    (
                        api,
                        ProgressApi {
                            totals: ApiTotals {
                                runs: SuccessCounts {
                                    executed: progress.runs.executed,
                                    passed: progress.runs.passed,
                                },
                                cases: SuccessCounts {
                                    executed: progress.cases.executed,
                                    passed: progress.cases.passed,
                                },
                            },
                            success_streak: SuccessStreak {
                                runs: progress.runs.success_streak,
                                cases: progress.cases.success_streak,
                            },
                        },
                    )
                })
                .collect(),
            requires_persistence: false,
        }
    }
}

pub(super) fn parse(payload: &[u8], stage: VerificationStage) -> Result<ProgressReport> {
    let value: serde_yaml::Value = serde_yaml::from_slice(payload)?;
    let version = value
        .get("version")
        .and_then(serde_yaml::Value::as_u64)
        .context("progress version is missing")?;
    if version == u64::from(PROGRESS_VERSION) && value.get("stage").is_none() {
        let public: Snapshot = serde_yaml::from_value(value)?;
        return Ok(public.into_report(stage));
    }
    serde_yaml::from_value(value).map_err(Into::into)
}
