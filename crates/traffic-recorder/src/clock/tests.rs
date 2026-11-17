use super::*;

#[test]
fn reverse_completion_retains_dependency_identity_and_global_event_order() {
    let clock = RecordingClock::default();
    let global = clock.next_dependency().unwrap();
    let begin_global = clock.event((global, "begin")).unwrap();
    let case = clock.next_dependency().unwrap();
    let begin_case = clock.event((case, "begin")).unwrap();
    let end_case = clock.event((case, "end")).unwrap();
    let end_global = clock.event((global, "end")).unwrap();
    assert_eq!([global, case], [1, 2]);
    assert_eq!(
        [
            begin_global.sequence,
            begin_case.sequence,
            end_case.sequence,
            end_global.sequence
        ],
        [1, 2, 3, 4]
    );
    assert!(begin_global.offset_micros <= end_global.offset_micros);
}

#[test]
fn cloned_clocks_share_one_recording_and_unique_concurrent_allocations() {
    let clock = RecordingClock::default();
    let recording_id = clock.recording_id();
    let threads = (0..4)
        .map(|_| {
            let shared = clock.clone();
            std::thread::spawn(move || {
                assert_eq!(shared.recording_id(), recording_id);
                (0..1_000)
                    .map(|_| shared.next_dependency().unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let mut sequences = threads
        .into_iter()
        .flat_map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=4_000).collect::<Vec<_>>());
}
