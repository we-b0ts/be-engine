//! Bounded custom inbound signatures; key values remain in startup inputs.
use super::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSignedTimestampEffect {
    pub algorithm: InputTimestampAlgorithm,
    /// Signature parameter names mapped to exact JSON string pointers.
    #[serde(deserialize_with = "crate::strict_map::unique_map")]
    pub fields: BTreeMap<String, String>,
    pub timestamp_pointer: String,
    pub signature_pointer: String,
    pub secret_parameter: String,
    pub signing_key: StartupKey,
    pub time: InputTokenTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputTimestampAlgorithm {
    /// UTF-8, trimmed strings, sorted `key=value` fields joined with `&`,
    /// followed by `&secret_parameter=<startup key>`, lowercase MD5 hex.
    Md5SortedFields,
}
