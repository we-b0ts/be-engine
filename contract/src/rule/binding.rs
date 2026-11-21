//! Borrowed value contracts supplied independently of carrier selection and compilation.
use std::{collections::BTreeMap, sync::Arc};

use crate::codec::{Codec, CodecPlan};

use super::{FieldContract, TimeContract};

#[derive(Clone, Copy)]
pub struct RuleBinding<'a> {
    pub id: &'a str,
    pub codec: &'a Codec,
    pub codec_plan: &'a Arc<CodecPlan>,
    pub fields: &'a BTreeMap<String, FieldContract>,
    pub delivery_time: &'a BTreeMap<String, TimeContract>,
}

pub trait ValueRule {
    fn binding(&self) -> RuleBinding<'_>;
}

impl ValueRule for RuleBinding<'_> {
    fn binding(&self) -> RuleBinding<'_> {
        *self
    }
}
