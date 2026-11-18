use anyhow::Result;
use serde_json::Value;

pub(super) enum CapturePlan {
    Breeze(Box<crate::BreezeResourceCapturePlan>),
    HttpResponse(super::http_response::Plan),
}

impl CapturePlan {
    pub(super) fn resource_identity(&self) -> &str {
        match self {
            Self::Breeze(plan) => &plan.report().resource_identity,
            Self::HttpResponse(plan) => plan.report["resource_identity"]
                .as_str()
                .unwrap_or_default(),
        }
    }
    pub(super) fn has_current_bypass(&self) -> bool {
        matches!(self, Self::Breeze(plan) if !plan.report().bypassed_domains_before.is_empty())
    }
    pub(super) fn report(&self) -> Result<Value> {
        match self {
            Self::Breeze(plan) => Ok(serde_json::to_value(plan.report())?),
            Self::HttpResponse(plan) => Ok(plan.report.clone()),
        }
    }
    pub(super) fn apply(self) -> Result<Value> {
        match self {
            Self::Breeze(plan) => Ok(serde_json::to_value(plan.apply()?)?),
            Self::HttpResponse(plan) => plan.apply(),
        }
    }
}
