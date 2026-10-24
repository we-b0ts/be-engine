//! Offline payload checks do not prove one accepted case-wide identity graph.
use super::*;

pub(super) fn require_replay(
    policy: &CompiledPolicy,
    selected: &BTreeSet<String>,
    result: &mut Preflight,
) {
    // Protected witnesses include rejected speculative candidates. Combining
    // every locally valid pair would invent accepted edges and can reject a
    // legitimate policy. Keep per-payload validation and require genuine Replay
    // to establish the shared correspondence, input anchors and successful admission.
    if selected.contains(crate::policy::GLOBAL_JSON_ID)
        && policy
            .global_json
            .as_ref()
            .is_some_and(|json| json.fields.values().any(|field| field.is_identity()))
    {
        result
            .stateful_target_obligations
            .insert(crate::policy::GLOBAL_JSON_ID.into());
    }
    if selected.contains("global.mysql")
        && policy.mysql.as_ref().is_some_and(|mysql| {
            mysql
                .tables
                .values()
                .any(|table| table.fields.values().any(|field| field.is_identity()))
        })
    {
        result
            .stateful_target_obligations
            .insert("global.mysql".into());
    }
    if selected.contains("global.redis")
        && policy
            .redis
            .as_ref()
            .is_some_and(|redis| redis.keys.values().any(|field| field.is_identity()))
    {
        result
            .stateful_target_obligations
            .insert("global.redis".into());
    }
    if selected.contains(crate::policy::GLOBAL_HTTP_ID)
        && policy
            .http
            .as_ref()
            .is_some_and(|http| http.headers.values().any(|field| field.is_identity()))
    {
        result
            .stateful_target_obligations
            .insert(crate::policy::GLOBAL_HTTP_ID.into());
    }
}
