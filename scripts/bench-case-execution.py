#!/usr/bin/env python3
"""Measure complete synthetic HTTP Cases against two central-only Replay binaries.

Each Case includes optional in-Case prefetch, begin/lazy preparation, request_begin,
a real HTTP target request whose handler uses Redis/MySQL wire I/O, an independent
status/content-type/exact-body assertion, and end acknowledgement. Both binaries
receive byte-identical synthetic inputs and separate persistent index directories.
All inputs, logs, reports and raw samples stay under --work-dir. No project target,
DNS interception, iptables or external dependency is used.

Coverage is intentionally finite: MySQL UPDATE/OK and Redis GET/bulk, plus MySQL
JSON literals and Redis SET JSON with authored UUID/time formats. PB, Motan,
complex stateful rules and pre-match
costs remain separate integration/performance workloads. This is an independent
primary HTTP assertion, not the complete managed E2E assertion adapter matrix.
"""
import argparse
import base64
from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import http.client
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

# Imported development helpers must not leave runtime artifacts in the checkout.
sys.dont_write_bytecode = True
from case_execution_benchmark_fixtures import WORKLOADS, create_fixture, input_hashes, json_bytes


def wire_helpers():
    path = Path(__file__).with_name("bench-replay-performance.py")
    specification = importlib.util.spec_from_file_location("replay_benchmark_wire", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


WIRE = wire_helpers()


def resp_command(stream, *arguments):
    arguments = [argument if isinstance(argument, bytes) else argument.encode() for argument in arguments]
    stream.sendall(f"*{len(arguments)}\r\n".encode() + b"".join(
        f"${len(argument)}\r\n".encode() + argument + b"\r\n" for argument in arguments))


def resp_reply(reader):
    line = reader.readline(1024 * 1024)
    if not line.endswith(b"\r\n"):
        raise RuntimeError("Incomplete synthetic Redis reply")
    kind, value = line[:1], line[1:-2]
    if kind == b"-":
        raise RuntimeError(f"Redis rejected synthetic request: {value.decode(errors='replace')}")
    if kind == b"$":
        length = int(value)
        if length == -1:
            return None
        if not 0 <= length <= 1024 * 1024:
            raise RuntimeError("Synthetic Redis bulk exceeds the benchmark bound")
        payload = reader.read(length + 2)
        if len(payload) != length + 2 or not payload.endswith(b"\r\n"):
            raise RuntimeError("Incomplete synthetic Redis bulk")
        return payload[:-2]
    if kind == b"+":
        return value
    raise RuntimeError(f"Unexpected synthetic Redis reply kind: {kind!r}")


def dependency_calls(program, case):
    """The target derives its result from actual wire replies, never the oracle."""
    results = []
    started = time.perf_counter()
    if program["workload"].startswith("mysql-"):
        with WIRE.mysql_login(program["replay_port"]) as client:
            for call in case["calls"]:
                if program["workload"] == "mysql-json":
                    value = json_bytes({
                        "request_id": str(uuid.UUID(int=0x200000 + call["ordinal"], version=4)),
                        "created_at": int(time.time()), "ordinal": call["ordinal"],
                    }).decode()
                    sql = f"UPDATE benchmark_entries SET payload='{value}' WHERE item={call['ordinal']}"
                else:
                    sql = call["sql"]
                WIRE.send_packet(client, b"\x03" + sql.encode())
                reply = WIRE.read_packet(client)
                if reply[:2] != b"\x00\x01":
                    raise RuntimeError("Synthetic UPDATE must deliver OK with one affected row")
                results.append(reply[1])
    else:
        with socket.create_connection(("127.33.0.1", program["replay_port"]), timeout=300) as client:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with client.makefile("rb") as reader:
                for call in case["calls"]:
                    arguments = [call["command"], call["key"]]
                    if program["workload"] == "redis-json":
                        arguments.append(json_bytes({
                            "request_id": str(uuid.UUID(int=0x200000 + call["ordinal"], version=4)),
                            "created_at": int(time.time()), "ordinal": call["ordinal"],
                        }))
                    resp_command(client, *arguments)
                    reply = resp_reply(reader)
                    if reply is None:
                        raise RuntimeError("Synthetic Redis result unexpectedly became nil")
                    results.append(reply.decode())
    return results, (time.perf_counter() - started) * 1000


def serve_target(specification, ready):
    program = json.loads(specification.read_text())
    if program.get("kind") != "traffic-e2e-synthetic-http-target/v1":
        raise RuntimeError("Only explicit synthetic target programs may execute")

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *_arguments):
            pass

        def do_POST(self):
            if self.path != "/__shutdown":
                self.send_error(404)
                return
            self.send_response(204)
            self.end_headers()
            threading.Thread(target=self.server.shutdown, daemon=True).start()

        def do_GET(self):
            case_id = self.path.removeprefix("/case/")
            case = program["cases"].get(case_id) if self.path.startswith("/case/") else None
            if case is None:
                self.send_error(404)
                return
            try:
                results, dependency_ms = dependency_calls(program, case)
                body = json_bytes({"case_id": case_id, "completed": len(results), "results": results})
                status = 200
            except Exception as error:
                body = json_bytes({"synthetic_target_error": str(error)})
                status, dependency_ms = 502, 0
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Synthetic-Dependency-Ms", f"{dependency_ms:.6f}")
            self.end_headers()
            self.wfile.write(body)

    with HTTPServer(("127.0.0.1", program["target_port"]), Target) as server:
        WIRE.write_json(ready, {"pid": os.getpid(), "port": program["target_port"]})
        server.serve_forever(poll_interval=0.01)


def wait_ready(process, paths, timeout=300):
    deadline = time.perf_counter() + timeout
    while not all(path.exists() for path in paths):
        if process.poll() is not None:
            raise RuntimeError("Synthetic process exited before readiness; inspect benchmark logs")
        if time.perf_counter() >= deadline:
            raise TimeoutError("Synthetic process readiness exceeded the benchmark timeout")
        time.sleep(0.01)


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def resources(path):
    user, system, rss = path.read_text().strip().split()
    return {"cpu_ms": (float(user) + float(system)) * 1000, "cpu_resolution_ms": 10, "peak_rss_kib": int(rss)}


def source_locations(root):
    locations, offset = [], 0
    with (root / "dependencies.jsonl").open("rb") as stream:
        for line, raw in enumerate(stream, 1):
            event = json.loads(raw)
            capture = event["capture"]
            locations.append({
                "index": len(locations), "case_id": capture["attribution"]["origin_case_id"],
                "event": event, "locator": {"line": line, "offset": offset, "length": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(), "exchange_id": capture["exchange_id"],
                    "effect_index": capture["effect_index"]},
            })
            offset += len(raw)
    return locations


def semantic_evidence(report, root, workload, expected_count, clock_window):
    """Bind every selected native position back to its exact original physical fact."""
    locations = source_locations(root)
    mysql = workload.startswith("mysql-")
    section = report if mysql else report["redis"]
    rows = report["matched_queries"] if mysql else section.get("matched", [])
    count = report["matched_query_count"] if mysql else section["matched_count"]
    unmatched = report["unmatched_queries"] if mysql else section.get("unmatched", [])
    unused = report["unused_case_exchanges"] if mysql else section.get("unused_case", [])
    if count != expected_count or len(rows) != expected_count or unmatched or unused:
        raise RuntimeError("Synthetic Case lost complete native matches/consumption or gained a mismatch")
    if not report["complete"] or not report["finalized"]:
        raise RuntimeError("Synthetic Replay did not complete and finalize")
    if report.get("batch_reconciliation", {}).get("dependency_inventory_verified") is not True:
        raise RuntimeError("Synthetic Replay did not verify the complete original dependency inventory")
    witnesses = report.get("policy_witnesses") or {}
    if witnesses.get("complete") is not True or witnesses.get("omitted") != 0:
        raise RuntimeError("Synthetic Case lost complete policy evidence coverage")
    if report.get("dependency_pre_matches") or report.get("dependency_hypothesis_coverage_error"):
        raise RuntimeError("Authored/strict benchmark unexpectedly used provisional hypotheses")
    if report.get("target_observation_coverage_error"):
        raise RuntimeError("Independent Target observation coverage is incomplete")
    unrelated_rejections = sum(len(report.get(name, [])) for name in (
        "unsupported_commands", "unmatched_http_requests", "unsupported_http_exchanges", "unrecorded_targets", "case_execution_failures"))
    if unrelated_rejections or section.get("unsupported") or section.get("unsafe_events"):
        raise RuntimeError("Synthetic Replay contains an unexpected rejection outside the measured native matches")
    decisions = []
    selected = set()
    for ordinal, row in enumerate(rows):
        index = row["index"]
        if not 0 <= index < len(locations) or index in selected:
            raise RuntimeError("Native selection duplicated or escaped the physical Source inventory")
        if index != ordinal:
            raise RuntimeError("The sequential synthetic HTTP program selected a different original Source ordinal")
        selected.add(index)
        original, event = locations[index], locations[index]["event"]
        if row["case_id"] != original["case_id"] or row["source"] != "case" or row["command"] != event["command"]:
            raise RuntimeError("Native selection changed original Source ownership/operation")
        if mysql:
            if row["status"] != event["response"]["status"]:
                raise RuntimeError("MySQL selected a different physical SQL contract or did not consume it")
            if workload == "mysql-json":
                prefix, suffix = "UPDATE benchmark_entries SET payload='", f"' WHERE item={ordinal}"
                actual_sql = row["sql"]
                if not actual_sql.startswith(prefix) or not actual_sql.endswith(suffix):
                    raise RuntimeError("MySQL changed a protected SQL statement or predicate")
                payload = json.loads(actual_sql[len(prefix):-len(suffix)])
                if (set(payload) != {"ordinal", "request_id", "created_at"}
                        or type(payload["ordinal"]) is not int or payload["ordinal"] != ordinal
                        or payload["request_id"] != str(uuid.UUID(int=0x200000 + ordinal, version=4))
                        or type(payload["created_at"]) is not int
                        or not int(clock_window[0]) - 1 <= payload["created_at"] <= int(clock_window[1]) + 1):
                    raise RuntimeError("MySQL JSON changed protected values or failed independent UUID/time checks")
            elif row["sql"] != event["sql"]:
                raise RuntimeError("MySQL changed its strict SQL request")
            if row.get("source_connection_id") != event["connection_id"] or row.get("source_query_sequence") != event["query_sequence"]:
                raise RuntimeError("MySQL selected a different physical Source connection/sequence")
        elif row["connection_id"] != event["connection_id"] or row["sequence"] != event["sequence"]:
            raise RuntimeError("Redis selected a different physical lane/sequence")
        fields = ("case_id", "source", "index", "target", "command", "status", "sql", "params", "database", "username", "connection_id", "sequence", "source_connection_id", "source_query_sequence")
        decision = {field: row[field] for field in fields if field in row}
        if workload == "mysql-json":
            # Raw Target SQL and its exact clocks remain in the original report.
            # Compare the physical Source selection and independently checked
            # semantics across runs whose permitted timestamps may differ.
            decision["sql"] = event["sql"]
            decision["target_generated_fields_verified"] = ["request_id:uuid", "created_at:unix_seconds"]
        decisions.append({"decision": decision, "source": original["locator"]})
    if selected != set(range(len(locations))):
        raise RuntimeError("Synthetic Source physical coverage is incomplete")
    coverage = {key: witnesses.get(key) for key in ("complete", "sealed", "omitted", "observed", "recorded")}
    semantic = {
        "complete": report["complete"], "finalized": report["finalized"],
        "cases": [{"case_id": case["case_id"], "status": case["status"]} for case in report["cases"]],
        "matched": decisions, "unmatched": unmatched, "unused": unused, "coverage": coverage,
        "dependency_inventory_verified": True,
        "hypotheses_used": len(report.get("dependency_pre_matches", [])),
    }
    return semantic, hashlib.sha256(json_bytes(semantic)).hexdigest()


def run(binary, label, repeat, fixture, args):
    started_wall = time.time()
    locations = fixture["copies"][label]
    project, source = Path(locations["project"]), Path(locations["source"])
    output = project / ".traffic-e2e/local/runtime" / f"sample-{repeat}"
    report_dir = output / "replay"
    report_dir.mkdir(parents=True)
    report, session = report_dir / "report.json", report_dir / "session.json"
    control = args.work_dir.resolve() / f".control-{uuid.uuid4().hex[:12]}.sock"
    if len(str(control).encode()) >= 108:
        raise RuntimeError("Use a shorter --work-dir so its Unix control socket fits 107 bytes")
    replay_usage, target_usage = output / "replay-resources.txt", output / "target-resources.txt"
    ready = output / "target-ready.json"
    cache = project / ".traffic-e2e/local/dependency-index"
    cache_before = WIRE.directory_bytes(cache)
    command = [str(binary), "replay", "--no-intercept", "--dns-listen", "127.0.0.1:0",
        "--tcp-listen", f"127.33.0.1:{fixture['replay_port']}", "--fake-cidr", "127.33.0.0/16",
        "--report", str(report), "--session", str(session), "--control-socket", str(control),
        "--case-dependency-post-response-window-ms", "0", "--policy", locations["policy"]]
    if args.lazy_cases:
        command.append("--lazy-case-dependencies")
    command.append(str(source))
    started = time.perf_counter()
    target_process = None
    case_samples = []
    with (output / "replay.log").open("wb") as replay_log, (output / "target.log").open("wb") as target_log:
        replay_process = subprocess.Popen(["/usr/bin/time", "-f", "%U %S %M", "-o", str(replay_usage), *command], stdout=replay_log, stderr=replay_log, start_new_session=True)
        try:
            wait_ready(replay_process, [control, session])
            WIRE.control(control, "wait_ready")
            replay_ready = time.perf_counter()
            target_process = subprocess.Popen([
                "/usr/bin/time", "-f", "%U %S %M", "-o", str(target_usage),
                sys.executable, str(Path(__file__).resolve()), "--serve-target", fixture["program"], "--ready", str(ready),
            ], stdout=target_log, stderr=target_log, start_new_session=True)
            wait_ready(target_process, [ready])
            target_ready = time.perf_counter()
            for case_id in fixture["case_ids"]:
                case_started = time.perf_counter()
                oracle = json.loads((source / case_id / "expected-response.json").read_text())
                expected_body = base64.b64decode(oracle["body"]["data"])
                oracle_done = time.perf_counter()
                prefetch_started = oracle_done
                prefetch = WIRE.control(control, "prefetch", case_id) if args.prefetch else None
                begin_started = time.perf_counter()
                WIRE.control(control, "begin", case_id)
                begin_done = time.perf_counter()
                WIRE.control(control, "request_begin", case_id)
                request_started = time.perf_counter()
                with closing(http.client.HTTPConnection("127.0.0.1", fixture["target_port"], timeout=300)) as client:
                    client.request("GET", f"/case/{case_id}")
                    response = client.getresponse()
                    body = response.read()
                    status, content_type = response.status, response.getheader("Content-Type")
                    dependency_ms = float(response.getheader("X-Synthetic-Dependency-Ms", "nan"))
                request_done = time.perf_counter()
                if not math.isfinite(dependency_ms) or dependency_ms < 0:
                    raise RuntimeError("Synthetic target did not report a valid dependency duration")
                if status != oracle["status"] or content_type != oracle["headers"]["content-type"][0] or body != expected_body:
                    WIRE.write_json(output / "assertion-failure.json", {
                        "case_id": case_id, "status": status, "content_type": content_type,
                        "actual_body_base64": base64.b64encode(body).decode(), "expected_response": oracle,
                    })
                    raise RuntimeError(f"Independent primary HTTP assertion failed for {case_id}: status={status} body={body[:256]!r}")
                assertion_done = time.perf_counter()
                WIRE.control(control, "end", case_id)
                case_done = time.perf_counter()
                case_samples.append({
                    "case_id": case_id, "case_ms": (case_done - case_started) * 1000,
                    "oracle_prepare_ms": (oracle_done - case_started) * 1000,
                    "prefetch_ms": (begin_started - prefetch_started) * 1000,
                    "prepare_ms": (begin_done - begin_started) * 1000,
                    "request_begin_ms": (request_started - begin_done) * 1000,
                    "http_request_ms": (request_done - request_started) * 1000,
                    "dependency_ms": dependency_ms, "assert_ms": (assertion_done - request_done) * 1000,
                    "end_ms": (case_done - assertion_done) * 1000,
                    "primary_assertion": "passed", "response_sha256": hashlib.sha256(body).hexdigest(),
                    "prefetch": prefetch, "lazy_cases": args.lazy_cases,
                })
            finalized = time.perf_counter()
            WIRE.control(control, "finalize")
            replay_process.wait(timeout=300)
            if replay_process.returncode:
                raise RuntimeError("Replay exited unsuccessfully; inspect replay.log")
            with closing(http.client.HTTPConnection("127.0.0.1", fixture["target_port"], timeout=10)) as client:
                client.request("POST", "/__shutdown")
                response = client.getresponse()
                response.read()
                if response.status != 204:
                    raise RuntimeError("Synthetic target shutdown was not acknowledged")
            target_process.wait(timeout=10)
            if target_process.returncode:
                raise RuntimeError("Synthetic target exited unsuccessfully; inspect target.log")
        except Exception as error:
            interrupted = None
            if replay_process.poll() is None and control.exists():
                try:
                    interrupted = WIRE.control(control, "interrupt")
                except Exception as snapshot_error:
                    interrupted = {"error": str(snapshot_error)}
            WIRE.write_json(output / "failure.json", {"error": str(error), "case_samples": case_samples,
                "report": str(report), "interrupted_evidence": interrupted})
            raise
        finally:
            stop_process(target_process)
            stop_process(replay_process)
            control.unlink(missing_ok=True)
    finished = time.perf_counter()
    value = json.loads(report.read_text())
    try:
        semantic, fingerprint = semantic_evidence(value, source, fixture["workload"],
            fixture["cases"] * fixture["queries"], (started_wall, time.time()))
    except Exception as error:
        WIRE.write_json(output / "failure.json", {"error": str(error), "case_samples": case_samples,
            "report": str(report), "source": str(source)})
        raise
    WIRE.write_json(output / "semantic-evidence.json", semantic)
    shared = WIRE.shared_reference_bytes(value, report)
    source_bytes = WIRE.directory_bytes(source)
    input_bytes = source_bytes + Path(locations["policy"]).stat().st_size + (
        project / ".traffic-e2e/local/secrets/traffic-e2e-enc.sec").stat().st_size
    replay_evidence = WIRE.directory_bytes(report_dir) + shared
    return {
        "binary": label, "workload": fixture["workload"], "cases": fixture["cases"], "queries": fixture["queries"],
        "repeat": repeat, "cache_state": "empty_persistent_index" if cache_before == 0 else "persistent_index_reuse",
        "os_page_cache": "uncontrolled; fixture creation/hash reads may warm it", "lazy_cases": args.lazy_cases,
        "prefetch_state": "requested_inside_each_measured_case" if args.prefetch else "not_requested",
        "replay_startup_ms": (replay_ready - started) * 1000, "target_startup_ms": (target_ready - replay_ready) * 1000,
        "finalize_and_shutdown_ms": (finished - finalized) * 1000, "wall_ms": (finished - started) * 1000,
        "case_samples": case_samples, "case_ms": {f"p{p}": WIRE.percentile([row["case_ms"] for row in case_samples], p) for p in (50, 95)},
        "replay_resources": resources(replay_usage), "target_resources": resources(target_usage),
        "index_cache_new_bytes": WIRE.directory_bytes(cache) - cache_before,
        "report_bytes": report.stat().st_size, "replay_evidence_bytes": replay_evidence,
        "shared_referenced_bytes": shared, "source_fixture_bytes": source_bytes,
        "prepared_input_bytes": input_bytes, "total_evidence_bytes": replay_evidence + input_bytes,
        "semantic_sha256": fingerprint, "witness_coverage": semantic["coverage"],
        "unmatched_count": len(semantic["unmatched"]), "unused_count": len(semantic["unused"]),
    }


def main():
    if "--serve-target" in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("--serve-target", type=Path, required=True)
        parser.add_argument("--ready", type=Path, required=True)
        args = parser.parse_args()
        serve_target(args.serve_target, args.ready)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--workloads", nargs="+", choices=WORKLOADS, default=list(WORKLOADS))
    parser.add_argument("--case-counts", nargs="+", type=int, default=[1, 16, 128])
    parser.add_argument("--queries", type=int, default=16,
                        help="1..100 dependency calls per Case, retaining complete native report details")
    parser.add_argument("--repeats", type=int, default=3, help="Measured repeats after the initial persistent-cache build")
    parser.add_argument("--lazy-cases", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--prefetch", action="store_true", help="Request prefetch inside each timed Case before begin")
    args = parser.parse_args()
    if min(*args.case_counts, args.queries, args.repeats) < 1:
        parser.error("case counts, queries and repeats must be positive")
    if args.queries > 100:
        parser.error("queries must not exceed the per-Case successful-detail limit of 100; every selected Source fact is compared")
    if len(set(args.workloads)) != len(args.workloads) or len(set(args.case_counts)) != len(args.case_counts):
        parser.error("workloads and case counts must not contain duplicates")
    if not Path("/usr/bin/time").is_file():
        parser.error("/usr/bin/time is required for separate Replay/target CPU and peak RSS")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(work.iterdir()):
        parser.error("Use an empty work directory to preserve cache-state provenance")
    binaries = {label: path.resolve(strict=True) for label, path in (("baseline", args.baseline), ("candidate", args.candidate))}
    result = {
        "schema": "traffic-case-execution-benchmark/v1",
        "settings": vars(args) | {"baseline": str(binaries["baseline"]), "candidate": str(binaries["candidate"]), "work_dir": str(work)},
        "binary_sha256": {label: WIRE.checksum(path) for label, path in binaries.items()},
        "versions": {label: subprocess.check_output([str(path), "--version"], text=True).strip() for label, path in binaries.items()},
        "coverage": ["HTTP primary exact status/content-type/body", "MySQL UPDATE/OK", "MySQL JSON literals authored UUID/time", "Redis GET/bulk", "Redis SET JSON authored UUID/time"],
        "limitations": ["No PB/Motan or complex stateful rule matrix", "No pre-match cost measurement", "No managed E2E assertion-adapter matrix", "OS page-cache state is uncontrolled"],
        "samples": [], "summaries": [],
    }
    fixtures = []
    for count in args.case_counts:
        for workload in args.workloads:
            replay_port = WIRE.free_port()
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                target_port = port_socket.getsockname()[1]
            fixture = create_fixture(work, workload, count, args.queries, replay_port, target_port)
            fixture["input_hashes"] = input_hashes(fixture, WIRE.checksum)
            fixtures.append(fixture)
    result["fixtures"] = fixtures
    result_path = work / "benchmark-results.json"
    WIRE.write_json(result_path, result)
    for repeat in range(args.repeats + 1):
        for fixture in fixtures:
            labels = ("baseline", "candidate") if repeat % 2 == 0 else ("candidate", "baseline")
            for label in labels:
                if WIRE.checksum(binaries[label]) != result["binary_sha256"][label]:
                    raise RuntimeError(f"The {label} binary changed during measurement; freeze it before comparing")
                if input_hashes(fixture, WIRE.checksum) != fixture["input_hashes"]:
                    raise RuntimeError("Immutable synthetic Source inputs changed before Replay")
                sample = run(binaries[label], label, repeat, fixture, args)
                sample["warmup"] = repeat == 0
                if WIRE.checksum(binaries[label]) != result["binary_sha256"][label]:
                    raise RuntimeError(f"The {label} binary changed during its sample")
                result["samples"].append(sample)
                if input_hashes(fixture, WIRE.checksum) != fixture["input_hashes"]:
                    raise RuntimeError("Replay changed immutable synthetic Source inputs")
                peers = [row for row in result["samples"] if row["workload"] == fixture["workload"] and row["cases"] == fixture["cases"]]
                if len({row["semantic_sha256"] for row in peers}) != 1:
                    raise RuntimeError("Case Source selection, consumption or evidence coverage changed")
                WIRE.write_json(result_path, result)
                print(json.dumps(sample), flush=True)
    for fixture in fixtures:
        for label in binaries:
            samples = [row for row in result["samples"] if row["workload"] == fixture["workload"] and row["cases"] == fixture["cases"] and row["binary"] == label and not row["warmup"]]
            cases = [case for sample in samples for case in sample["case_samples"]]
            summary = {"workload": fixture["workload"], "cases": fixture["cases"], "binary": label,
                "case_samples": len(cases), "lazy_cases": args.lazy_cases, "prefetch_inside_case": args.prefetch,
                "case_ms": {f"p{p}": WIRE.percentile([case["case_ms"] for case in cases], p) for p in (50,95)},
                "stages_ms": {name: {f"p{p}": WIRE.percentile([case[name] for case in cases], p) for p in (50,95)} for name in ("oracle_prepare_ms", "prepare_ms", "request_begin_ms", "http_request_ms", "dependency_ms", "assert_ms", "end_ms", "prefetch_ms")},
                "last_case_ms": {f"p{p}": WIRE.percentile([sample["case_samples"][-1]["case_ms"] for sample in samples], p) for p in (50,95)},
                "resources_p50": {process: {metric: WIRE.percentile([sample[process][metric] for sample in samples], 50) for metric in ("cpu_ms", "peak_rss_kib")} for process in ("replay_resources", "target_resources")},
                "evidence_bytes_p50": {metric: WIRE.percentile([sample[metric] for sample in samples], 50) for metric in ("report_bytes", "replay_evidence_bytes", "source_fixture_bytes", "total_evidence_bytes")}}
            result["summaries"].append(summary)
            print(json.dumps({"summary": summary}), flush=True)
    WIRE.write_json(result_path, result)


if __name__ == "__main__":
    main()
