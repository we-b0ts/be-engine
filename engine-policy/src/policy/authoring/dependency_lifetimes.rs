//! Integrated authoring regressions use application-composed registries and admission.
use crate::policy::native::*;
use crate::policy::*;
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;
pub use traffic_policy_document::authoring::dependency_lifetimes::*;

mod tests;

use sha2::{Digest, Sha256};
