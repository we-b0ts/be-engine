use crate::http::sse::SseObservation;

use super::model::{ResponseAssertionCaseReport, ResponseDifference, ResponseDifferenceKind};

pub(super) fn compare(
    expected: Option<SseObservation>,
    actual: Option<SseObservation>,
    report: &mut ResponseAssertionCaseReport,
) {
    match (expected, actual) {
        (Some(expected), Some(actual)) => {
            if expected.window_ms != actual.window_ms {
                report.differences.push(difference(
                    "$sse_observation/window_ms",
                    ResponseDifferenceKind::SseObservationMismatch,
                ));
            }
            if expected.end != actual.end {
                report.differences.push(difference(
                    "$sse_observation/end",
                    ResponseDifferenceKind::SseStreamEndMismatch,
                ));
            }
        }
        (None, None) => {}
        _ => report.differences.push(difference(
            "$sse_observation",
            ResponseDifferenceKind::SseObservationMismatch,
        )),
    }
}

fn difference(pointer: &str, kind: ResponseDifferenceKind) -> ResponseDifference {
    ResponseDifference {
        pointer: pointer.to_string(),
        kind,
        expected_type: None,
        actual_type: None,
        expected_status: None,
        actual_status: None,
    }
}
