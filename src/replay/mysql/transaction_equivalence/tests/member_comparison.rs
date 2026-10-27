use super::*;

fn strict_values() -> Vec<Value> {
    let mut values = records();
    values[1]["sql"] = json!("SELECT id FROM users WHERE id=1 FOR UPDATE");
    values
}

#[test]
fn consumed_but_reordered_members_report_the_first_actual_difference() {
    let mut r = registry(&strict_values());
    segment(&mut r, &mut Witness::default(), &[2, 1, 3], "COMMIT");
    let proof = r.diagnostic(3).unwrap();
    let group = &proof["source_transactions"][0];
    assert_eq!(group["missing_required_query_sequences"], json!([]));
    let comparison = &group["member_comparison"];
    assert_eq!(comparison["first_difference"]["member_position"], 0);
    assert_eq!(
        comparison["first_difference"]["expected"]["source_query_sequence"],
        5
    );
    assert_eq!(
        comparison["first_difference"]["actual"]["source_query_sequence"],
        6
    );
    assert_eq!(comparison["source_member_count"], 3);
    assert_eq!(comparison["target_member_count"], 3);
    assert_eq!(comparison["observed_end"], "commit");
    assert_eq!(proof["covered_transaction_count"], 0);
    let text = serde_json::to_string(comparison).unwrap();
    assert!(!text.contains("UPDATE"));
    assert!(!text.contains("SELECT"));
}

#[test]
fn a_different_matched_end_keeps_its_original_source_reference() {
    let mut r = registry(&strict_values());
    segment(&mut r, &mut Witness::default(), &[1, 2, 7], "COMMIT");
    let proof = r.diagnostic(3).unwrap();
    let difference = &proof["source_transactions"][0]["member_comparison"]["first_difference"];
    assert_eq!(difference["member_position"], 2);
    assert_eq!(difference["expected"]["source_query_sequence"], 7);
    assert_eq!(difference["actual"]["source_query_sequence"], 11);
    assert_eq!(difference["actual"]["recorded_index"], 7);
}

#[test]
fn member_lists_are_bounded_but_a_later_first_difference_remains_visible() {
    let original = strict_values();
    let mut values = original[..2].to_vec();
    for index in 0..80 {
        let mut update = original[2].clone();
        update["query_sequence"] = json!(6 + index);
        values.push(update);
    }
    let mut end = original[3].clone();
    end["query_sequence"] = json!(86);
    values.push(end);
    let mut r = registry(&values);
    let mut indices = (1..values.len()).collect::<Vec<_>>();
    indices.swap(40, 41);
    segment(&mut r, &mut Witness::default(), &indices, "COMMIT");
    let proof = r.diagnostic(values.len() - 1).unwrap();
    let comparison = &proof["source_transactions"][0]["member_comparison"];
    assert_eq!(comparison["source_members"].as_array().unwrap().len(), 32);
    assert_eq!(comparison["target_members"].as_array().unwrap().len(), 32);
    assert_eq!(comparison["source_members_omitted"], 50);
    assert_eq!(comparison["target_members_omitted"], 50);
    assert_eq!(comparison["first_difference"]["member_position"], 40);
    assert_eq!(
        comparison["first_difference"]["expected"]["source_query_sequence"],
        45
    );
    assert_eq!(
        comparison["first_difference"]["actual"]["source_query_sequence"],
        46
    );
}
