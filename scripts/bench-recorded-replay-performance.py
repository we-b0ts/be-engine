#!/usr/bin/env python3
"""Run one captured API per fresh test process; retain only private measurements."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import re


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    args.output = args.output.resolve()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.label):
        raise ValueError("benchmark label must be a simple filename component")
    if any((parent / ".git").exists() for parent in (args.output, *args.output.parents)):
        raise ValueError("sensitive benchmark outputs must stay outside git repositories")
    marker = args.output / ".recorded-benchmark-results"
    if args.output.exists() and any(args.output.iterdir()) and not marker.is_file():
        raise ValueError("use an empty dedicated output directory")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.output.stat().st_mode & 0o077:
        raise ValueError("benchmark output directory must be private (mode 0700)")
    marker.touch(mode=0o600)
    data = json.loads(args.input.read_text())
    files = {Path(data["policy"]), args.input}
    for workload in data["workloads"]:
        root = Path(workload["case_root"])
        for case in workload["case_ids"]:
            files.update(root / case / name for name in ("request.json", "expected-response.json", "dependencies.jsonl"))
        for parent in (root, *root.parents):
            if (parent / "recording-run.json").is_file():
                files.update(parent / name for name in ("recording-run.json", "recording-network.json", "global-dependencies.jsonl") if (parent / name).is_file())
                break
    before = {str(path): digest(path) for path in files}
    measurements = []
    for index, workload in enumerate(data["workloads"]):
        path = args.output / f"{args.label}-input-{index}.json"
        path.write_text(json.dumps(dict(data, repeats=1, workloads=[workload])))
        for repeat in range(args.repeats):
            output = args.output / f"{args.label}-{index}-{repeat}.json"
            log = args.output / f"{args.label}-{index}-{repeat}.log"
            env = dict(os.environ, TRAFFIC_E2E_RECORDED_PERF_INPUT=str(path), TRAFFIC_E2E_RECORDED_PERF_OUTPUT=str(output))
            with log.open("wb") as stream:
                subprocess.run(["/usr/bin/time", "-v", "-o", str(log.with_suffix(".resources")), str(args.binary), "--ignored", "--nocapture", "captured_candidate_and_evidence_performance"], env=env, stdout=stream, stderr=stream, check=True)
            result = json.loads(output.read_text())[0]
            result.update(repeat=repeat, binary=args.label)
            measurements.append(result)
            (args.output / f"{args.label}.json").write_text(json.dumps(measurements, indent=2))
            print(json.dumps({"api": result["api"], "repeat": repeat,
                              "match_ms": round(sum(case["match_ms"] for case in result["cases"]), 2),
                              "artifact_bytes": result["artifact_bytes"], "witness_complete": result["witness_complete"]}), flush=True)
    after = {str(path): digest(path) for path in files}
    assert after == before, "immutable benchmark inputs changed"
    (args.output / f"{args.label}-input-integrity.json").write_text(json.dumps({"unchanged": True, "files": len(files), "sha256": before}, indent=2))


if __name__ == "__main__":
    main()
