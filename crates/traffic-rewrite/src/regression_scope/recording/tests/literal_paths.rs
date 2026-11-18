use super::*;

#[test]
fn finalized_recording_with_literal_404_path_is_admitted_without_rewriting_evidence() {
    for scoped in [false, true] {
        let root = target();
        let paths = ["/api/v1/auth/tokens/", "/api/v1/auth/tokens", "/api//other"];
        let scope = if scoped {
            vec![
                "GET /api/v1/auth/tokens/",
                "GET /api/v1/auth/tokens",
                "GET /api//other",
            ]
        } else {
            vec![]
        };
        record(root.path(), A, &scope, &paths, "completed");
        let run = artifacts::recording_run(root.path(), A);
        let mut before = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let case = run.join("apis/cases").join(format!("case-{index}"));
            fs::write(
                case.join("request.json"),
                serde_json::json!({"method":"GET","uri":path,"api_pattern":path}).to_string(),
            )
            .unwrap();
            fs::write(case.join("expected-response.json"),serde_json::json!({"status":404,"body":{"encoding":"utf8","data":"{\"detail\":\"Not Found\"}","truncated":false}}).to_string()).unwrap();
            for file in ["request.json", "expected-response.json"] {
                let p = case.join(file);
                before.push((p.clone(), fs::read(p).unwrap()));
            }
        }
        policy(root.path(), A, "skip: [/api/v1/auth/tokens/]\n");
        validate_uninitialized(root.path()).unwrap();
        let mut state = workflow_test_support::test_state();
        assert!(super::super::super::apply(root.path(), &mut state).unwrap());
        let apis = artifacts::standard_recording_apis(root.path(), &state).unwrap();
        assert_eq!(
            apis,
            vec![
                "GET /api//other",
                "GET /api/v1/auth/tokens",
                "GET /api/v1/auth/tokens/"
            ]
        );
        inventory::install(&mut state, apis).unwrap();
        super::super::super::apply(root.path(), &mut state).unwrap();
        assert!(super::super::super::is_skipped(
            &state,
            "GET /api/v1/auth/tokens/"
        ));
        assert!(!super::super::super::is_skipped(
            &state,
            "GET /api/v1/auth/tokens"
        ));
        for (p, bytes) in before {
            assert_eq!(fs::read(p).unwrap(), bytes);
        }
    }
}

#[test]
fn skip_never_bypasses_recording_path_or_membership_validation() {
    for recorded in ["/api/v1/auth/tokens", "/api/bad path"] {
        let root = target();
        record(
            root.path(),
            A,
            &["GET /api/v1/auth/tokens/"],
            &[recorded],
            "completed",
        );
        policy(root.path(), A, "skip: [/api/v1/auth/tokens/]\n");
        assert!(validate_uninitialized(root.path()).is_err(), "{recorded}");
        let mut state = workflow_test_support::test_state();
        let before = serde_json::to_value(&state).unwrap();
        assert!(super::super::super::apply(root.path(), &mut state).is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}
