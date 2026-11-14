use super::*;
use crate::dependency_index::{RecordReader, RecordSource, global::NotificationEntry};
use crate::protocols::replay::report::redis::notifications::RedisEvidence;
use crate::replay::redis::pubsub::{
    NotificationDelta, NotificationIdentity, NotificationLaneEvidence, NotificationSessionEvidence,
};
use crate::replay::report::command::CommandUnusedReport;
use crate::replay::{ReplaySource, TargetKey};
use serde_json::json;
use std::fs;
use std::sync::Mutex as StdMutex;
use uuid::Uuid;
mod protocol;

struct Fixture {
    root: tempfile::TempDir,
    source: std::path::PathBuf,
    report: std::path::PathBuf,
    lanes: Vec<NotificationLaneEvidence>,
    expected: Vec<Value>,
}

fn capture(bytes: &[u8]) -> Value {
    use base64::Engine as _;
    json!({"encoding":"base64","data":base64::engine::general_purpose::STANDARD.encode(bytes),"truncated":false})
}

impl Fixture {
    fn new() -> Self {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let owner = root.path().join(".traffic-e2e");
        let recording = owner.join("recordings/run");
        fs::create_dir_all(&recording).unwrap();
        let source = recording.join("global-dependencies.jsonl");
        let mut output = std::io::BufWriter::new(fs::File::create(&source).unwrap());
        for (lane, count) in [600, 3].into_iter().enumerate() {
            let connection = Uuid::from_u128(lane as u128 + 1);
            let confirmation = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n";
            let subscription = json!({"event_type":"redis_exchange","connection_id":connection,"sequence":1,
                "target_host":"redis.test","target_port":6379,"database":0,"username":null,"resp_version":2,
                "command":"SUBSCRIBE","args":[capture(b"jobs")],"response":capture(confirmation),
                "response_kind":"array","duration_ms":0,"replay_safe":true});
            writeln!(output, "{subscription}").unwrap();
            for position in 0..count {
                let raw = crate::redis::encode_array(&[
                    b"message",
                    b"jobs",
                    position.to_string().as_bytes(),
                ]);
                writeln!(output, "{}", json!({"event_type":"redis_pub_sub_push","connection_id":connection,
                    "subscription_sequence":1,"target_host":"redis.test","target_port":6379,"database":0,
                    "username":null,"response":capture(&raw),"duration_ms":position,"replay_safe":true})).unwrap();
            }
        }
        output.flush().unwrap();
        drop(output);
        let (index, directory) = crate::dependency_index::global::load_global_index(
            &source,
            crate::protocols::replay::source::validate_index_record,
        )
        .unwrap();
        let reader = Arc::new(StdMutex::new(RecordReader::new(1024)));
        let original = RecordSource::new(&source, index.stamp, reader);
        let mut lanes = Vec::new();
        let mut expected = vec![json!({"index":9000}), json!({"index":9001})];
        for (lane_index, lane) in index.notifications.into_iter().enumerate() {
            let pages =
                Paged::<NotificationEntry>::restore(lane.pages.resolve(&directory).unwrap())
                    .unwrap();
            let identity = NotificationIdentity {
                target: TargetKey {
                    host: "redis.test".into(),
                    port: 6379,
                },
                database: 0,
                username: None,
                connection_id: Uuid::parse_str(lane.record["connection_id"].as_str().unwrap())
                    .unwrap(),
                subscription_sequence: 1,
                kind: "channel".into(),
                subject: b"jobs".to_vec(),
                subscription_proof: json!({"command":"SUBSCRIBE","args":[capture(b"jobs")],
                    "response_kind":"array","response":capture(b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n")}),
            };
            let mut position = 0;
            for page in 0..pages.pages() {
                for entry in pages.read_page(page).unwrap() {
                    if lane_index != 0 || ![0, 255, 256, 599].contains(&position) {
                        expected.push(
                            serde_json::to_value(CommandUnusedReport {
                                source_exchange_id: None,
                                index: entry.location.line - 1,
                                case_id: None,
                                source: ReplaySource::Startup,
                                target: identity.target.clone(),
                                connection_id: identity.connection_id,
                                sequence: 1,
                                command: "PUBSUB_PUSH".into(),
                            })
                            .unwrap(),
                        );
                    }
                    position += 1;
                }
            }
            lanes.push(NotificationLaneEvidence {
                source: original.clone(),
                pages,
                identity,
            });
        }
        expected.push(json!({"index":9999,"case_id":null,"source":"startup",
            "background_original_case_id":"case-a","background_rule":"background"}));
        let report = owner.join("local/runs/first/reports/replay-report.json");
        fs::create_dir_all(report.parent().unwrap()).unwrap();
        Self {
            root,
            source,
            report,
            lanes,
            expected,
        }
    }

    fn session(&self) -> NotificationSessionEvidence {
        NotificationSessionEvidence {
            lanes: self
                .lanes
                .iter()
                .map(|lane| NotificationLaneEvidence {
                    source: lane.source.clone(),
                    pages: lane.pages.clone(),
                    identity: lane.identity.clone(),
                })
                .collect(),
            deltas: vec![NotificationDelta {
                lane: 0,
                consumed: vec![0, 255, 256, 599],
                failed: vec![257],
                responding: vec![258],
            }],
            recorded: 603,
            delivered: 4,
            failed: 1,
        }
    }

    fn prepare(&self) -> RedisEvidence {
        let parent = self.report.parent().unwrap();
        let mut writer = PageWriter::new_in(&parent.join("global-dependencies")).unwrap();
        for item in self.expected.iter().take(2) {
            writer.push(item.clone()).unwrap();
        }
        let ordinary = writer.finish().unwrap();
        let manifest = ordinary.persist().relative_to(parent).unwrap();
        let compact = RedisEvidence::prepare(&self.report, manifest, self.session())
            .unwrap()
            .unwrap();
        fs::write(
            &self.report,
            serde_json::to_vec(&json!({"finalized":true,
            "global_evidence":{"redis":compact}, "redis":{"unused_global_count":self.expected.len(),
                "unused_global":[self.expected[0],self.expected.last().unwrap()]}}))
            .unwrap(),
        )
        .unwrap();
        compact
    }
}

#[test]
fn compact_pages_preserve_counts_order_and_unused_failed_responding_across_all_boundaries() {
    let fixture = Fixture::new();
    let compact = fixture.prepare();
    assert!(serde_json::to_vec(&compact).unwrap().len() < 4096);
    for offset in [0, 1, 2, 250, 256, 598, 600, 601, 602] {
        for limit in [1, 3, 1000] {
            let page =
                read_global_dependency_page(&fixture.report, "redis", offset, limit).unwrap();
            let expected: Vec<_> = fixture
                .expected
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect();
            assert_eq!(page.total, fixture.expected.len());
            assert_eq!(page.items, expected, "offset={offset} limit={limit}");
            assert_eq!(
                page.next_offset,
                (offset + page.returned < page.total).then_some(offset + page.returned)
            );
        }
    }
    assert!(read_global_dependency_page(&fixture.report, "redis", 603, 1).is_err());
}

#[test]
fn warm_prepare_and_same_owner_publication_do_not_visit_shared_notification_pages() {
    let fixture = Fixture::new();
    let stamp = crate::dependency_index::FileStamp::read(&fixture.source).unwrap();
    let first = fixture.prepare();
    let (_, shared) = first.load(&fixture.report).unwrap();
    let page = shared.join("lane-0/0.json");
    let parked = shared.join("parked-page");
    fs::rename(&page, &parked).unwrap();
    let second = fixture.prepare();
    assert_eq!(
        serde_json::to_value(&first).unwrap()["notifications"]["inventory"],
        serde_json::to_value(&second).unwrap()["notifications"]["inventory"]
    );
    let destination = fixture
        .root
        .path()
        .join(".traffic-e2e/local/runs/second/reports/replay-report.json");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    assert!(
        stage_global_evidence(&fixture.report, &destination)
            .unwrap()
            .is_none()
    );
    assert!(read_global_dependency_page(&fixture.report, "redis", 2, 1).is_err());
    fs::rename(parked, page).unwrap();
    assert_eq!(
        crate::dependency_index::FileStamp::read(&fixture.source).unwrap(),
        stamp
    );
}

#[test]
fn standalone_export_survives_source_and_cache_removal_and_snapshot_rename() {
    let fixture = Fixture::new();
    fixture.prepare();
    let export = tempfile::tempdir().unwrap();
    let active = export.path().join(".active");
    let destination = active.join("reports/replay-report.json");
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    let rebound = stage_global_evidence(&fixture.report, &destination)
        .unwrap()
        .unwrap();
    fs::write(&destination, serde_json::to_vec(&rebound).unwrap()).unwrap();
    let expected = fixture.expected.clone();
    fixture.root.close().unwrap();
    let latest = export.path().join("latest");
    fs::rename(active, &latest).unwrap();
    let page =
        read_global_dependency_page(&latest.join("reports/replay-report.json"), "redis", 0, 1000)
            .unwrap();
    assert_eq!(page.items, expected);
}

#[test]
fn shared_manifest_and_lazy_pages_keep_sha_guards_and_source_drift_is_rejected() {
    let fixture = Fixture::new();
    let compact = fixture.prepare();
    let (_, shared) = compact.load(&fixture.report).unwrap();
    let page = shared.join("lane-0/0.json");
    let original = fs::read(&page).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["payload"][0]["location"]["line"] = json!(123456);
    fs::write(&page, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(read_global_dependency_page(&fixture.report, "redis", 2, 1).is_err());
    fs::write(&page, original).unwrap();
    let manifest = shared.join("manifest.json");
    let original = fs::read(&manifest).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["payload"]["source"]["bytes"] = json!(0);
    crate::dependency_index::store::write_json(&manifest, &changed["payload"]).unwrap();
    assert!(compact.load(&fixture.report).is_err());
    fs::write(manifest, original).unwrap();
    fs::write(&fixture.source, "changed\n").unwrap();
    assert!(RedisEvidence::prepare(&fixture.report, compact.pages, fixture.session()).is_err());
}
