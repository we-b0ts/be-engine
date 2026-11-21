use super::*;

impl WitnessStore {
    pub fn segment_limit_for_test(&self, limit: u64) {
        self.state
            .lock()
            .unwrap()
            .segmented
            .as_mut()
            .unwrap()
            .segment_limit(limit);
    }
    #[allow(dead_code)]
    pub fn fail_writes_for_test(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.file = File::open(&state.path)?;
        if let Some(writer) = &mut state.segmented {
            writer.fail_writes()?;
        }
        Ok(())
    }
}

#[test]
fn unavailable_source_identity_cache_is_bounded_and_never_promotes_changed_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let store = WitnessStore::new(temp.path()).unwrap();
    let mut metadata = WitnessMetadata {
        surface: Surface::DependencyRequest,
        source_role: SourceRole::DependencyRequest,
        target_role: TargetRole::Unavailable,
        source: SourceIdentity {
            case_id: "case".into(),
            exchange_id: None,
            connection_id: Some("connection".into()),
            sequence: Some(0),
        },
        resource: None,
        operation: "SET".into(),
        slot: Slot::Value,
        clocks: Default::default(),
    };
    let oversized = vec![0; MAX_PAYLOAD + 1];
    for sequence in 0..=MAX_OBSERVATIONS {
        metadata.source.sequence = Some(sequence as u64);
        assert!(
            store
                .record(metadata.clone(), temp.path(), &oversized, None)
                .unwrap()
                .is_none()
        );
    }
    {
        let state = store.state.lock().unwrap();
        assert_eq!(
            state.sources.len() + state.unavailable_sources.len(),
            MAX_OBSERVATIONS
        );
        assert!(state.source_tracking_exhausted);
    }
    let before = store.manifest().unwrap();
    metadata.source.sequence = Some(0);
    assert!(
        store
            .record(
                metadata.clone(),
                temp.path(),
                b"different small bytes",
                None
            )
            .unwrap()
            .is_none()
    );
    metadata.source.sequence = Some(MAX_OBSERVATIONS as u64 + 2);
    assert!(
        store
            .record(
                metadata,
                temp.path(),
                b"new identity after tracking bound",
                None
            )
            .unwrap()
            .is_none()
    );
    let after = store.sealed_manifest().unwrap();
    assert_eq!(
        (before.observed, before.omitted),
        (after.observed, after.omitted)
    );
    assert!(!after.complete);
    assert!(after.observations.as_ref().unwrap().sources.is_empty());
}
