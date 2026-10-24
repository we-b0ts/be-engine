#!/usr/bin/env python3
"""Compare two Replay binaries on immutable, synthetic, isolated workloads.

Uses loopback and --no-intercept only. Never starts a project target or modifies
DNS/iptables. Original fixtures are hashed before/after; generated output is
removed after measurement unless --keep-artifacts is supplied.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import statistics
import struct
import subprocess
import time
import uuid


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, separators=(",", ":")) + "\n")


def checksum(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def capture(raw):
    return {"encoding": "base64", "data": base64.b64encode(raw).decode(), "truncated": False}


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.33.0.1", 0))
        return stream.getsockname()[1]


def make_fixture(project, kind, args):
    root = project / ".traffic-e2e/local/artifacts/recordings" / kind
    root.mkdir(parents=True, exist_ok=True)
    host, port = "sql.benchmark.invalid", free_port()
    case_ids = [f"case-{index:04d}" for index in range(args.cases if kind == "sql" else 1)]
    queries = []
    for index, case_id in enumerate(case_ids):
        case = root / case_id
        case.mkdir()
        write_json(case / "request.json", {"method": "GET", "uri": "/benchmark", "body": capture(b"")})
        write_json(case / "expected-response.json", {})
        lines, calls = [], []
        if kind == "sql":
            columns = ", ".join(f"entries.column_{n:03d} AS column_{n:03d}" for n in range(90))
            for number in range(args.queries):
                sql = f"SELECT {columns} FROM entries WHERE id={number}"
                calls.append(sql)
                lines.append({"event_type": "mysql_exchange", "connection_id": str(uuid.UUID(int=index + 1)),
                              "query_sequence": number + 1, "target_host": host, "target_port": port,
                              "database": "benchmark", "username": "root", "command": "COM_QUERY", "sql": sql,
                              "timestamp": "2026-10-17T00:00:00Z", "duration_ms": 0,
                              "response": {"status": "ok", "affected_rows": 0, "last_insert_id": 0}})
        (case / "dependencies.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))
        queries.append(list(reversed(calls)))
    policy = None
    if kind == "sql":
        local = project / ".traffic-e2e/local/secrets"
        local.mkdir(parents=True, exist_ok=True)
        key = local / "traffic-e2e-enc.sec"
        key.write_text(base64.b64encode(os.urandom(32)).decode())
        key.chmod(0o600)
        policy = project / ".traffic-e2e/policy.yaml"
        text = "format: traffic-policy/v2\nsource_revision: benchmark-v1\nrules:\n"
        for number in range(19):
            text += (f"- id: global-write-time-{number}\n"
                     f"  match:\n    resource: {{protocol: mysql, endpoint: '{host}:{port}', database: benchmark, username: root}}\n"
                     f"    operation: COM_QUERY\n    sql: UPDATE entries_{number:02d} SET stamp=? WHERE id=7\n"
                     "  effect:\n    kind: mysql_values\n    values:\n      0: {relative_time: unix_seconds}\n"
                     "  proof: {source: 'benchmark/service.rs:1-10', fact: 'Synthetic Source writes the request clock'}\n")
        policy.write_text(text)
    elif kind == "pubsub":
        host = "redis.benchmark.invalid"
        lane = str(uuid.UUID(int=99))
        confirm = b"*3\r\n$9\r\nsubscribe\r\n$4\r\njobs\r\n:1\r\n"
        message = b"*3\r\n$7\r\nmessage\r\n$4\r\njobs\r\n$7\r\npayload\r\n"
        subscription = {"event_type": "redis_exchange", "connection_id": lane, "sequence": 1,
                        "target_host": host, "target_port": port, "database": 0, "username": None,
                        "resp_version": 2, "command": "SUBSCRIBE", "args": [capture(b"jobs")],
                        "response": capture(confirm), "response_kind": "array", "duration_ms": 0, "replay_safe": True}
        push = {"event_type": "redis_pub_sub_push", "connection_id": lane, "subscription_sequence": 1,
                "target_host": host, "target_port": port, "database": 0, "username": None,
                "response": capture(message), "duration_ms": 60000, "replay_safe": True}
        line = json.dumps(push, separators=(",", ":")) + "\n"
        with (root / "global-dependencies.jsonl").open("w") as output:
            output.write(json.dumps(subscription) + "\n")
            for _ in range(args.notifications):
                output.write(line)
    else:
        host = "redis.benchmark.invalid"
        lane = str(uuid.UUID(int=101))
        with (root / "global-dependencies.jsonl").open("w") as output:
            for number in range(args.global_exchanges):
                key = f"process-cache:{number:08d}:" + "x" * 128
                record = {"event_type": "redis_exchange", "connection_id": lane,
                          "sequence": number + 1, "target_host": host, "target_port": port,
                          "database": 0, "username": None, "resp_version": 2,
                          "command": "GET", "args": [capture(key.encode())],
                          "response": capture(b"$7\r\npayload\r\n"), "response_kind": "bulk_string",
                          "duration_ms": 0, "replay_safe": True}
                output.write(json.dumps(record, separators=(",", ":")) + "\n")
    write_json(root / "recording-network.json", {"version": 1, "resolved_domains": [host],
                                                "accessed_endpoints": [{"host": host, "port": port}]})
    return root, case_ids, queries, port, policy


def control(path, command, case=None):
    request = {"command": command, "fail_on_dirty": False, "fail_on_incomplete": False}
    if case is not None:
        request["case_id"] = case
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(300)
        stream.connect(str(path))
        stream.sendall(json.dumps(request).encode() + b"\n")
        stream.shutdown(socket.SHUT_WR)
        data = bytearray()
        while chunk := stream.recv(65536):
            data.extend(chunk)
    response = json.loads(data)
    if not response.get("ok"):
        raise RuntimeError(f"Replay control {command}: {response.get('error')}")
    return response


def read_packet(stream):
    def exact(length):
        value = bytearray()
        while len(value) < length:
            chunk = stream.recv(length - len(value))
            if not chunk:
                raise RuntimeError("Replay MySQL connection closed")
            value.extend(chunk)
        return bytes(value)
    header = exact(4)
    return exact(int.from_bytes(header[:3], "little"))


def send_packet(stream, payload, sequence=0):
    stream.sendall(len(payload).to_bytes(3, "little") + bytes([sequence]) + payload)


def mysql_login(port):
    stream = socket.create_connection(("127.33.0.1", port), timeout=300)
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    read_packet(stream)
    flags = 0x200 | 0x8000 | 0x8 | 0x80000
    login = struct.pack("<II", flags, 0) + bytes([45]) + bytes(23)
    login += b"root\0\0benchmark\0mysql_native_password\0"
    send_packet(stream, login, 1)
    if read_packet(stream)[0] != 0:
        raise RuntimeError("Replay MySQL login failed")
    return stream


def directory_bytes(path):
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file()) if path.exists() else 0


def semantic_report(report):
    # Compare protocol decisions, original selected identities and exact SQL;
    # runtime wall clocks, session UUIDs and witness storage layout differ.
    common = ("case_id", "target", "database", "username", "command", "sql", "params")
    queries = lambda name, fields: [{k: row.get(k) for k in fields}
                            for row in report.get(name, [])]
    value = {"complete": report["complete"], "finalized": report["finalized"],
             "cases": [(row["case_id"], row["status"]) for row in report["cases"]],
             "matched_count": report["matched_query_count"],
             "matched": queries("matched_queries", common + ("source", "index", "status")),
             "unmatched": queries("unmatched_queries", common + ("reason", "recorded_source", "recorded_index")),
             "unused_mysql": len(report["unused_case_exchanges"]),
             "redis_unused": report["redis"].get("unused_global_count"),
             "pubsub": report["redis"].get("pubsub"),
             "rules": report.get("replay_policy")}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(binary, label, index, fixture, project, args):
    root, case_ids, queries, port, policy = fixture
    output = project / ".traffic-e2e/local/runtime" / f"{root.name}-{label}-{index}"
    output.mkdir(parents=True)
    report, session = output / "replay.json", output / "session.json"
    sock = Path("/tmp") / f"trp-bench-{uuid.uuid4().hex}.sock"
    command = [str(binary), "replay", "--no-intercept", "--dns-listen", "127.0.0.1:0",
               "--tcp-listen", f"127.33.0.1:{port}", "--fake-cidr", "127.33.0.0/16",
               "--report", str(report), "--session", str(session), "--control-socket", str(sock),
               "--case-dependency-post-response-window-ms", "0"]
    if policy:
        command += ["--policy", str(policy)]
    command.append(str(root))
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    shared_root = project / ".traffic-e2e/local/artifacts/shared-global-inventories"
    shared_before = directory_bytes(shared_root)
    started = time.perf_counter()
    with (output / "process.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = started + 300
            while not sock.exists() or not session.exists():
                if process.poll() is not None:
                    raise RuntimeError(f"Replay startup failed; inspect {output / 'process.log'}")
                if time.perf_counter() > deadline:
                    raise TimeoutError("Replay startup exceeded 300s")
                time.sleep(0.02)
            control(sock, "wait_ready")
            ready = time.perf_counter()
            durations = []
            for case_id, calls in zip(case_ids, queries):
                case_started = time.perf_counter()
                control(sock, "begin", case_id)
                if policy:
                    control(sock, "request_begin", case_id)
                    with mysql_login(port) as client:
                        for sql in calls:
                            send_packet(client, b"\x03" + sql.encode())
                            if read_packet(client)[0] != 0:
                                raise RuntimeError("Synthetic SQL unexpectedly failed to match")
                        send_packet(client, b"\x03SELECT unmatched_value FROM missing_table")
                        if read_packet(client)[0] != 0xFF:
                            raise RuntimeError("Unmatched SQL must remain a genuine mismatch")
                control(sock, "end", case_id)
                durations.append((time.perf_counter() - case_started) * 1000)
            cases_done = time.perf_counter()
            control(sock, "finalize")
            process.wait(timeout=300)
            if process.returncode:
                raise RuntimeError(f"Replay exited with {process.returncode}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            sock.unlink(missing_ok=True)
    finished = time.perf_counter()
    cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    value = json.loads(report.read_text())
    witness = value.get("policy_witnesses") or {}
    if policy and (witness.get("complete") is not True or witness.get("omitted") != 0):
        raise RuntimeError("SQL benchmark must retain complete policy evidence without omissions")
    if policy and (value["matched_query_count"] != sum(map(len, queries)) or
                   len(value["unmatched_queries"]) != len(case_ids)):
        raise RuntimeError("SQL benchmark changed matched or genuine mismatch counts")
    result = {"workload": root.name, "binary": label, "repeat": index,
              "startup_ms": (ready - started) * 1000, "cases_ms": durations,
              "finalize_ms": (finished - cases_done) * 1000, "wall_ms": (finished - started) * 1000,
              "cpu_ms": (cpu_after.ru_utime + cpu_after.ru_stime - cpu_before.ru_utime - cpu_before.ru_stime) * 1000,
              "report_bytes": report.stat().st_size, "artifact_bytes": directory_bytes(output),
              "shared_new_bytes": directory_bytes(shared_root) - shared_before,
              "semantic_sha256": semantic_report(value), "witness_complete": witness.get("complete"),
              "witness_omitted": witness.get("omitted"), "matched_queries": value.get("matched_query_count"),
              "unmatched_queries": len(value.get("unmatched_queries", []))}
    if not args.keep_artifacts:
        shutil.rmtree(output)
    return result


def input_hashes(project):
    return {str(p.relative_to(project)): checksum(p)
            for p in project.rglob("*") if p.is_file() and
            p.name in ("dependencies.jsonl", "global-dependencies.jsonl", "request.json", "expected-response.json", "policy.yaml", "recording-network.json", "traffic-e2e-enc.sec")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--notifications", type=int, default=65537)
    parser.add_argument("--global-exchanges", type=int, default=131073)
    parser.add_argument("--workloads", choices=("sql", "pubsub", "global"), nargs="+",
                        default=["sql", "pubsub"])
    parser.add_argument("--queries", type=int, default=54)
    parser.add_argument("--cases", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()
    if min(args.cases, args.queries, args.repeats) < 1 or min(args.notifications, args.global_exchanges) < 0:
        parser.error("cases, queries and repeats must be positive; inventory sizes must be nonnegative")
    project = args.work_dir.resolve()
    project.mkdir(parents=True, exist_ok=True, mode=0o700)
    result_path = project / "benchmark-results.json"
    if result_path.exists():
        saved = json.loads(result_path.read_text())
        if saved.get("semantic_version") != 2:
            raise RuntimeError("Benchmark comparison schema changed; remeasure both binaries")
        for key in ("cases", "queries", "notifications", "global_exchanges", "workloads"):
            if key in saved["settings"] and saved["settings"][key] != getattr(args, key):
                raise RuntimeError(f"Benchmark setting {key} changed; use a new work directory")
        fixtures = [(Path(x[0]), x[1], x[2], x[3], Path(x[4]) if x[4] else None) for x in saved["fixtures"]]
        if input_hashes(project) != saved["input_hashes"]:
            raise RuntimeError("Benchmark inputs changed")
    else:
        fixtures = [make_fixture(project, kind, args) for kind in args.workloads]
        saved = {"semantic_version": 2,
                 "settings": vars(args) | {"baseline": str(args.baseline), "candidate": str(args.candidate), "work_dir": str(project)},
                 "fixtures": [[str(a), b, c, d, str(e) if e else None] for a, b, c, d, e in fixtures],
                 "input_hashes": input_hashes(project), "samples": []}
        write_json(result_path, saved)
    for label, binary in [("baseline", args.baseline), ("candidate", args.candidate)]:
        if binary is None:
            continue
        binary_sha = checksum(binary.resolve())
        previous = saved.setdefault("binary_sha256", {}).get(label)
        if previous is not None and previous != binary_sha:
            raise RuntimeError(f"The {label} binary changed; use a new work directory")
        saved["binary_sha256"][label] = binary_sha
        saved.setdefault("versions", {})[label] = subprocess.check_output([str(binary.resolve()), "--version"], text=True).strip()
        for fixture in fixtures:
            for index in range(args.repeats + 1):
                if any(x["binary"] == label and x["workload"] == fixture[0].name and x["repeat"] == index for x in saved["samples"]):
                    continue
                sample = run(binary.resolve(), label, index, fixture, project, args)
                sample["warmup"] = index == 0
                saved["samples"].append(sample)
                write_json(result_path, saved)
                print(json.dumps(sample), flush=True)
    if input_hashes(project) != saved["input_hashes"]:
        raise RuntimeError("Replay changed immutable benchmark input")
    for fixture in fixtures:
        all_rows = [x for x in saved["samples"] if x["workload"] == fixture[0].name]
        rows = [x for x in all_rows if not x["warmup"]]
        fingerprints = {x["semantic_sha256"] for x in all_rows}
        if len(fingerprints) != 1:
            raise RuntimeError(f"Replay comparison semantics changed for {fixture[0].name}")
        for label in ("baseline", "candidate"):
            items = [x for x in rows if x["binary"] == label]
            if items:
                print(json.dumps({"summary": fixture[0].name, "binary": label,
                                  **{k: statistics.median(x[k] for x in items) for k in
                                     ("wall_ms", "cpu_ms", "startup_ms", "finalize_ms", "artifact_bytes", "report_bytes")}}))


if __name__ == "__main__":
    main()
