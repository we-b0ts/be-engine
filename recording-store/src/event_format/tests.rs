use super::*;

#[test]
fn event_types_have_positional_columns_and_round_trip() -> Result<()> {
    let run = Uuid::from_u128(1);
    let case_id = IdentityKind::Case.bridge(run, 2);
    let dependency_sequence = 1;
    let cases = [
        (
            CaptureEvent::PrimaryBoundary {
                case_id,
                boundary: PrimaryBoundary::ResponseEnd,
            },
            "primary_boundary\tcase-2\tresponse_end".to_owned(),
        ),
        (
            CaptureEvent::Input {
                case_id,
                input_sequence: 5,
                kind: InputKind::TransportEnd,
            },
            "primary_input\tcase-2\t5\ttransport_end".to_owned(),
        ),
        (
            CaptureEvent::Started {
                dependency_sequence,
                phase: CapturePhase::Startup,
                observed_case: None,
                admitted_case: None,
            },
            "capture_started\tstartup\t-\t-".to_owned(),
        ),
        (
            CaptureEvent::Started {
                dependency_sequence,
                phase: CapturePhase::Runtime,
                observed_case: Some(case_id),
                admitted_case: None,
            },
            "capture_started\truntime\tcase-2\t-".to_owned(),
        ),
        (
            CaptureEvent::MessageStarted {
                dependency_sequence,
            },
            "message_started".to_owned(),
        ),
        (
            CaptureEvent::OutputStarted {
                dependency_sequence,
                output: OutputKind::Headers,
            },
            format!("wire_output_started\t{dependency_sequence}\theaders"),
        ),
        (
            CaptureEvent::OutputCancelled {
                dependency_sequence,
                started_sequence: 2,
            },
            format!("wire_output_cancelled\t{dependency_sequence}\t2"),
        ),
        (
            CaptureEvent::Output {
                dependency_sequence,
                output: OutputKind::Terminated {
                    termination: DependencyTermination {
                        side: TerminationSide::Client,
                        kind: TerminationKind::Eof,
                        scope: TerminationScope::WriteHalf,
                    },
                },
            },
            format!("wire_output\t{dependency_sequence}\tterminated\tclient\teof\twrite_half"),
        ),
        (
            CaptureEvent::Terminal {
                dependency_sequence,
                outcome: "response".to_owned(),
                capture_complete: true,
            },
            format!("capture_terminated\t{dependency_sequence}\tresponse\t1"),
        ),
        (
            CaptureEvent::Terminal {
                dependency_sequence,
                outcome: "custom\toutcome\r\n".to_owned(),
                capture_complete: false,
            },
            format!("capture_terminated\t{dependency_sequence}\t\"custom\\toutcome\\r\\n\"\t0"),
        ),
        (CaptureEvent::Sealed, "capture_sealed".to_owned()),
    ];
    for (event, expected) in cases {
        let event = RecordedEvent {
            sequence: 1,
            offset_micros: 15_900_795,
            event,
        };
        let row = encode_event(&event, run)?;
        assert_eq!(row, format!("1\t15900795\t{expected}\n").as_bytes());
        assert_eq!(
            serde_json::to_value(decode_event(std::str::from_utf8(&row)?, run)?)?,
            serde_json::to_value(event)?
        );
    }
    Ok(())
}

#[test]
fn malformed_or_old_event_rows_are_rejected() {
    for row in [
        "1\t2\t{\"event_type\":\"capture_sealed\"}",
        "1\t2\tcapture_sealed\textra",
        "1\t2\tmessage_started\t00000000-0000-0000-0000-000000000001",
        "1\t2\tcapture_started\t00000000-0000-0000-0000-000000000001\t1\tstartup\tnull\t-",
        "1\t2\twire_output\t00000000-0000-0000-0000-000000000001\t1\tterminated\tclient\teof",
    ] {
        assert!(decode_event(row, Uuid::nil()).is_err(), "{row}");
    }
}
