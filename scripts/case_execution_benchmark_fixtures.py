"""Explicitly synthetic central-only inputs for the HTTP Case benchmark."""
import base64
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import uuid

from replay_benchmark_fixtures import central_fixture


WORKLOADS = ("mysql-strict", "mysql-json", "redis-strict", "redis-json")
STAMP = "2026-10-17T00:00:00Z"
SOURCE_SECONDS = int(datetime.fromisoformat(STAMP.replace("Z", "+00:00")).timestamp())


def encoded(value):
    return {"encoding": "base64", "data": base64.b64encode(value).decode(), "truncated": False}


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value) + b"\n")


def create_fixture(work, workload, cases, queries, replay_port, target_port):
    """Build once, then copy identical sealed input bytes to both binary projects.

    The target program contains operations only. It never contains primary
    response oracles; those are independently recorded in expected-response.json.
    """
    builder = work / "synthetic-build" / f"{workload}-{cases}"
    root = builder / ".traffic-e2e/local/artifacts/recordings" / f"{workload}-{cases}"
    root.mkdir(parents=True)
    write_json(root / "synthetic-benchmark.json", {"kind": "traffic-e2e-synthetic-benchmark"})
    host = "sql.case-benchmark.invalid" if workload.startswith("mysql-") else "redis.case-benchmark.invalid"
    identifiers, programs = [], {}
    for ordinal in range(cases):
        case_id = str(uuid.UUID(int=0x10000 + ordinal))
        identifiers.append(case_id)
        case = root / case_id
        case.mkdir()
        write_json(case / "request.json", {
            "method": "GET", "uri": f"/case/{case_id}", "headers": {},
            "body": encoded(b""), "request_started_at": STAMP,
        })
        connection = str(uuid.UUID(int=0x50000 + ordinal))
        records, calls, results = [], [], []
        for number in range(queries):
            identity = ordinal * queries + number
            if workload.startswith("mysql-"):
                if workload == "mysql-json":
                    value = json_bytes({
                        "request_id": str(uuid.UUID(int=0x100000 + identity, version=4)),
                        "created_at": SOURCE_SECONDS, "ordinal": identity,
                    }).decode()
                    sql = f"UPDATE benchmark_entries SET payload='{value}' WHERE item={identity}"
                    calls.append({"ordinal": identity})
                else:
                    sql = f"UPDATE benchmark_entries SET value=1 WHERE case_ordinal={ordinal} AND item={number}"
                    calls.append({"sql": sql})
                records.append({
                    "event_type": "mysql_exchange", "connection_id": connection,
                    "query_sequence": number + 1, "target_host": host, "target_port": replay_port,
                    "database": "benchmark", "username": "root", "command": "COM_QUERY", "sql": sql,
                    "timestamp": STAMP, "request_started_at": STAMP, "duration_ms": 0,
                    "response": {"status": "ok", "affected_rows": 1, "last_insert_id": 0},
                })
                results.append(1)
            else:
                key = f"case-benchmark:{ordinal}:item:{number}"
                if workload == "redis-strict":
                    value = f"value-{ordinal}-{number}"
                    command, args = "GET", [key]
                    response = f"${len(value)}\r\n{value}\r\n".encode()
                    calls.append({"command": command, "key": key})
                    results.append(value)
                else:
                    value = json_bytes({
                        "request_id": str(uuid.UUID(int=0x100000 + identity, version=4)),
                        "created_at": SOURCE_SECONDS, "ordinal": identity,
                    }).decode()
                    command, args = "SET", [key, value]
                    response = b"+OK\r\n"
                    calls.append({"command": command, "key": key, "ordinal": identity})
                    results.append("OK")
                records.append({
                    "event_type": "redis_exchange", "connection_id": connection,
                    "sequence": number + 1, "target_host": host, "target_port": replay_port,
                    "database": 0, "username": None, "resp_version": 2,
                    "command": command, "args": [encoded(arg.encode()) for arg in args],
                    "response": encoded(response), "response_kind": "bulk_string" if command == "GET" else "simple_string",
                    "timestamp": STAMP, "request_started_at": STAMP,
                    "duration_ms": 0, "replay_safe": True,
                })
        (case / "dependencies.jsonl").write_bytes(b"".join(json_bytes(record) + b"\n" for record in records))
        write_json(case / "expected-response.json", {
            "status": 200, "headers": {"content-type": ["application/json"]},
            "body": encoded(json_bytes({"case_id": case_id, "completed": queries, "results": results})),
        })
        programs[case_id] = {"calls": calls}
    write_json(root / "recording-network.json", {
        "version": 1, "resolved_domains": [host],
        "accessed_endpoints": [{"host": host, "port": replay_port}],
    })
    policy = builder / ".traffic-e2e/policy.yaml"
    policy.write_text(
        "format: traffic-policy/v3\nrules: []\n" +
        ("json:\n  fields:\n    /request_id: {kind: identity, formats: [uuid]}\n"
         "    /created_at: {kind: time, formats: [unix_seconds]}\n" if workload.endswith("-json") else "")
    )
    secret = builder / ".traffic-e2e/local/secrets/traffic-e2e-enc.sec"
    secret.parent.mkdir(parents=True)
    secret.write_bytes(base64.b64encode(os.urandom(32)))
    secret.chmod(0o600)
    central, *_ = central_fixture((root, identifiers, [], replay_port, policy), builder)
    specification = work / "synthetic-inputs" / f"{workload}-{cases}" / "target-program.json"
    write_json(specification, {
        "kind": "traffic-e2e-synthetic-http-target/v1", "workload": workload,
        "replay_port": replay_port, "target_port": target_port, "cases": programs,
    })
    copies = {}
    for label in ("baseline", "candidate"):
        project = work / label / f"{workload}-{cases}"
        destination = project / ".traffic-e2e/local/artifacts/recordings" / central.name
        destination.parent.mkdir(parents=True)
        shutil.copytree(central, destination)
        paired_policy = project / ".traffic-e2e/policy.yaml"
        shutil.copyfile(policy, paired_policy)
        paired_secret = project / ".traffic-e2e/local/secrets/traffic-e2e-enc.sec"
        paired_secret.parent.mkdir(parents=True)
        shutil.copyfile(secret, paired_secret)
        paired_secret.chmod(0o600)
        copies[label] = {"project": str(project), "source": str(destination), "policy": str(paired_policy)}
    return {
        "workload": workload, "cases": cases, "queries": queries, "case_ids": identifiers,
        "replay_port": replay_port, "target_port": target_port,
        "program": str(specification), "copies": copies,
    }


def input_hashes(fixture, checksum):
    inputs = {"program": checksum(Path(fixture["program"]))}
    for label, locations in fixture["copies"].items():
        root = Path(locations["source"])
        files = {str(path.relative_to(root)): checksum(path) for path in root.rglob("*") if path.is_file()}
        files["@policy"] = checksum(Path(locations["policy"]))
        files["@key"] = checksum(Path(locations["project"]) / ".traffic-e2e/local/secrets/traffic-e2e-enc.sec")
        inputs[label] = files
    if inputs["baseline"] != inputs["candidate"]:
        raise RuntimeError("Central Source inputs differ between benchmark binaries")
    return inputs
