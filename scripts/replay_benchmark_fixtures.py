"""Paired, explicitly synthetic fixture formats for the Replay comparison.

This adapter is development tooling, not a production recording migration. It
only accepts directories marked by the synthetic benchmark generator.
"""
import hashlib
import json
from pathlib import Path
import shutil
import uuid


def central_fixture(fixture, project):
    original, case_ids, queries, port, policy = fixture
    marker = original / "synthetic-benchmark.json"
    if json.loads(marker.read_text()).get("kind") != "traffic-e2e-synthetic-benchmark":
        raise ValueError("only generated synthetic benchmark fixtures may be adapted")
    paired = project / "central"
    root = paired / original.relative_to(project)
    if root.exists():
        raise ValueError("paired synthetic fixture already exists; use a fresh work directory")
    shutil.copytree(original, root, ignore=shutil.ignore_patterns(".*"))
    epoch = str(uuid.UUID(int=0x100000))
    records, scope_rows = [], {"startup": [], "process": [], "unattributed": []}
    offset = 0

    def write_json(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, separators=(",", ":")) + "\n")

    def append(event, owner, key):
        nonlocal offset
        exchange = str(uuid.UUID(int=0x200000 + len(records)))
        kind = event["event_type"]
        if kind == "http_exchange":
            native = {"protocol": "http", "exchange_id": event["id"]}
        elif kind == "mysql_exchange":
            native = {"protocol": "mysql", "connection_id": event["connection_id"], "sequence": event["query_sequence"]}
        elif kind == "redis_exchange":
            native = {"protocol": "redis", "connection_id": event["connection_id"], "sequence": event["sequence"]}
        else:
            native = {"protocol": "observation", "event_id": exchange, "kind": kind}
        event = dict(event)
        event["capture"] = {
            "exchange_id": exchange, "process_epoch": epoch,
            "phase": "runtime" if key in case_ids else "startup",
            "observed_case": key if key in case_ids else None,
            "admitted_case": key if key in case_ids else None,
            "started_at": event.get("timestamp", "2026-10-17T00:00:00Z"),
            "protocol_ref": native, "attribution": owner,
            "effect_index": 0, "semantic_required": True,
        }
        raw = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        scope_rows[key].append({"line": len(records) + 1, "offset": offset, "length": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(), "exchange_id": exchange,
                                "effect_index": 0})
        offset += len(raw)
        records.append(raw)

    for case in case_ids:
        uuid.UUID(case)
        scope_rows[case] = []
        file = root / case / "dependencies.jsonl"
        for line in file.read_text().splitlines():
            if line.strip():
                append(json.loads(line), {"kind": "case", "origin_case_id": case}, case)
        file.unlink()
    global_file = root / "global-dependencies.jsonl"
    if global_file.exists():
        for line in global_file.read_text().splitlines():
            if line.strip():
                append(json.loads(line), {"kind": "startup", "process_epoch": epoch,
                                         "initialization_unit": "synthetic_startup_inventory"}, "startup")
        global_file.unlink()
    (root / "dependencies.jsonl").write_bytes(b"".join(records))
    (root / "dependency-lifecycle.jsonl").write_text('{"kind":"synthetic_inventory_complete"}\n')
    for key, locations in scope_rows.items():
        case = key in case_ids
        path = root / key / "dependency-scope.json" if case else root / "indexes" / (key + "-scope.json")
        write_json(path, {"schema": "traffic-dependency-scope/v3", "run_relpath": "..",
                          "scope": {"kind": "case", "case_id": key} if case else {"kind": key},
                          "locations": locations})
    identities = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "synthetic-benchmark.json":
            content = path.read_bytes()
            identities.append({"path": str(path.relative_to(root)), "length": len(content),
                               "sha256": hashlib.sha256(content).hexdigest()})
    write_json(root / "dependency-manifest.json", {
        "schema": "traffic-recording/v3", "run_id": root.name,
        "run_epoch": str(uuid.UUID(int=0x100001)), "process_epochs": [epoch],
        "capture_policy_identity": "synthetic-benchmark-policy",
        "source_artifact": {"status": "unavailable", "reason": "explicitly synthetic protocol benchmark; no Source executable"},
        "sealed": True, "capture_complete": True,
        "coverage": {"admitted": len(records), "terminal": len(records), "capture_failures": 0,
                     "inventory_gaps": False, "pending": []},
        "records": len(records), "unattributed_records": 0,
        "semantic_inventory": {
            "total_mandatory": len(records),
            "by_owner_kind": {"case": sum(len(scope_rows[case]) for case in case_ids),
                              "startup": len(scope_rows["startup"]), "process": 0, "unattributed": 0},
            "unsupported_by_scope": {}, "unattributed_dependencies": 0,
        },
        "inputs": [{"case_id": case, "path": case, "complete": True} for case in case_ids],
        "files": identities,
    })
    write_json(root / "recording-run.json", {"schema": "traffic-recording/v3", "status": "completed",
                                             "run_id": root.name, "dependency_manifest": "dependency-manifest.json"})
    paired_policy = None
    if policy:
        paired_policy = paired / policy.relative_to(project)
        paired_policy.parent.mkdir(parents=True, exist_ok=True)
        paired_policy.write_text(policy.read_text().replace("traffic-policy/v2", "traffic-policy/v3"))
        original_key = project / ".traffic-e2e/local/secrets/traffic-e2e-enc.sec"
        key = paired / original_key.relative_to(project)
        key.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original_key, key)
        key.chmod(0o600)
    return root, case_ids, queries, port, paired_policy
