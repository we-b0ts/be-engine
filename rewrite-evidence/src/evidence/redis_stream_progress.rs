//! Bounded admission audits for the selected Case; never expose stream bytes.
use std::collections::BTreeMap;

use serde_json::{Value, json};

const MAX_STREAMS: usize = 16;
const MAX_FRAGMENTS: usize = 8;

pub fn facts(replay: &Value, case_id: &str) -> Value {
    let mut streams = BTreeMap::<&str, (usize, &Value)>::new();
    let mut case_audits = 0;
    for audit in replay["redis"]["append_streams"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|audit| audit["case_id"] == case_id)
    {
        let Some(key) = audit["source_key_fingerprint"].as_str() else {
            continue;
        };
        case_audits += 1;
        streams
            .entry(key)
            .and_modify(|(count, last)| {
                *count += 1;
                *last = audit;
            })
            .or_insert((1, audit));
    }
    let stream_count = streams.len();
    let streams = streams
        .into_iter()
        .take(MAX_STREAMS)
        .map(|(key, (count, last))| {
            let fragments = last["fragments"].as_array();
            let fragment_count = fragments.map_or(0, Vec::len);
            let fragments = fragments
                .into_iter()
                .flatten()
                .take(MAX_FRAGMENTS)
                .map(|fragment| {
                    json!({"source_connection":fragment["source_connection"],
                        "source_sequence":fragment["source_sequence"],
                        "source_offset":fragment["source_offset"],
                        "target_offset":fragment["target_offset"],"bytes":fragment["bytes"]})
                })
                .collect::<Vec<_>>();
            json!({"source_key_fingerprint":key,"retained_admission_count":count,
                "last_retained_admission":{
                    "rule_id":last["rule_id"],"target_observation":last["target_observation"],
                    "target_key_fingerprint":last["target_key_fingerprint"],
                    "payload_fingerprint":last["payload_fingerprint"],
                    "source_offset_before":last["from"],"source_offset_after":last["to"],
                    "returned_length":last["returned_length"],"source_fragments":fragments,
                    "omitted_source_fragments":fragment_count.saturating_sub(MAX_FRAGMENTS)}})
        })
        .collect::<Vec<_>>();
    let report_omitted = replay["redis"]["append_streams_omitted"].as_u64();
    json!({"case_id":case_id,"retained_admission_count":case_audits,
        "retained_key_fingerprint_groups":stream_count,"key_fingerprint_groups":streams,
        "omitted_key_fingerprint_groups":stream_count.saturating_sub(MAX_STREAMS),
        "report_omitted_admissions":report_omitted,
        "retained_audits_complete":report_omitted == Some(0),
        "association":"case-scoped admission audits; not a Source counterpart for the selected unmatched request",
        "grouping":"Source key fingerprint only; physical resource and state epoch ownership are not inferred",
        "does_not_prove":["Admission is not proof of successful transport delivery or Source exchange consumption.",
            "An omitted audit can advance a stream beyond its last retained admission; missing streams do not prove no writes.",
            "A byte cursor does not authorize reordering or adding other Redis commands."]})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_is_case_scoped_bounded_and_preserves_omission_uncertainty() {
        let fragments = (0..10)
            .map(|sequence| {
                json!({"source_connection":"conn","source_sequence":sequence,
                "source_offset":0,"target_offset":sequence,"bytes":1,"private":"stream bytes"})
            })
            .collect::<Vec<_>>();
        let mut audits = (0..18)
            .map(|key| {
                json!({"case_id":"selected","source_key_fingerprint":format!("key-{key:02}"),
                "rule_id":"append-rule","from":10,"to":20,"fragments":fragments,
                "private":"stream bytes"})
            })
            .collect::<Vec<_>>();
        audits.push(json!({"case_id":"foreign","source_key_fingerprint":"foreign-key", "to":999}));
        let mut replay = json!({"redis":{"append_streams":audits,"append_streams_omitted":3}});
        let progress = facts(&replay, "selected");
        assert_eq!(progress["retained_admission_count"], 18);
        assert_eq!(
            progress["key_fingerprint_groups"].as_array().unwrap().len(),
            16
        );
        assert_eq!(progress["omitted_key_fingerprint_groups"], 2);
        assert_eq!(progress["report_omitted_admissions"], 3);
        assert_eq!(progress["retained_audits_complete"], false);
        let admission = &progress["key_fingerprint_groups"][0]["last_retained_admission"];
        assert_eq!(admission["source_offset_after"], 20);
        assert_eq!(admission["source_fragments"].as_array().unwrap().len(), 8);
        assert_eq!(admission["omitted_source_fragments"], 2);
        assert!(!progress.to_string().contains("foreign-key"));
        assert!(!progress.to_string().contains("stream bytes"));
        replay["redis"]["append_streams_omitted"] = json!(0);
        assert_eq!(facts(&replay, "selected")["retained_audits_complete"], true);
        assert_eq!(
            facts(&json!({}), "legacy")["retained_audits_complete"],
            false
        );
    }
}
