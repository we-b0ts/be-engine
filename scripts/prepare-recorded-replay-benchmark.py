#!/usr/bin/env python3
"""Prepare private inputs for captured_candidate_and_evidence_performance.

Requires PyYAML and cryptography in a disposable Python environment. Reads
published observations and immutable recordings; never writes to the project.
The output contains sensitive genuine Target SQL. Keep it outside git.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def fingerprint(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def private_write(path, text):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--report", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    args.output = args.output.resolve()
    if any((parent / ".git").exists() for parent in (args.output, *args.output.parents)):
        raise ValueError("sensitive benchmark inputs must stay outside git repositories")
    marker = args.output / ".recorded-benchmark-inputs"
    if args.output.exists() and any(args.output.iterdir()) and not marker.is_file():
        raise ValueError("use an empty dedicated output directory")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.output.stat().st_mode & 0o077:
        raise ValueError("benchmark output directory must be private (mode 0700)")
    private_write(marker, "traffic-e2e private benchmark inputs\n")
    key = args.project / ".traffic-e2e/local/secrets/traffic-e2e-enc.sec"
    cipher = AESGCM(base64.b64decode(key.read_text()))
    policy = args.project / ".traffic-e2e/policy.yaml"
    document = yaml.safe_load(policy.read_text())
    source_effects = {"capture_http", "capture_http_response", "process_owned", "finite_sharing", "identity"}
    document["rules"] = [rule for rule in document["rules"]
                         if (isinstance(rule.get("match", {}).get("resource"), dict)
                             and rule["match"]["resource"].get("protocol") == "mysql")
                         or rule.get("effect", {}).get("kind") in source_effects]
    snapshot = args.output / "policy.yaml"
    private_write(snapshot, yaml.safe_dump(document, allow_unicode=True, sort_keys=False))
    workloads, inputs = [], {str(policy): fingerprint(policy)}
    for report in args.report:
        value = json.loads(report.read_text())
        manifest = value["policy_witnesses"]
        graph = manifest.get("observations")
        if graph is None:
            reference = manifest["graph_artifact"]
            directory = report.parent / reference["artifact"]
            assert directory.name == reference["artifact"]
            assert fingerprint(directory) == reference["sha256"]
            graph = json.loads(directory.read_text())
        artifact = report.parent / manifest["artifact"]
        assert fingerprint(artifact) == manifest["sha256"]
        inputs[str(report)] = fingerprint(report)
        inputs[str(artifact)] = manifest["sha256"]
        queries = []
        for node in graph["targets"]:
            metadata = node["metadata"]
            if (metadata["surface"] != "dependency.request"
                    or metadata["role"] != "independent_target_observation"
                    or metadata.get("resource", {}).get("protocol") != "mysql"):
                continue
            blob = graph["blobs"][node["blob"]]
            raw = bytearray()
            for chunk in blob.get("chunks") or [blob]:
                chunk_path = report.parent / chunk.get("artifact", manifest["artifact"])
                assert chunk_path.name == chunk.get("artifact", manifest["artifact"])
                with chunk_path.open("rb") as payload:
                    payload.seek(chunk["offset"])
                    line = payload.read(chunk["length"])
                assert "sha256:" + hashlib.sha256(line).hexdigest() == chunk["sha256"]
                envelope = json.loads(line)
                nonce, ciphertext = envelope["encrypted"].removeprefix("traffic-e2e:enc:v1:aes-256-gcm:").split(":")
                raw.extend(cipher.decrypt(base64.b64decode(nonce), base64.b64decode(ciphertext),
                                          f"traffic-policy-blob/v2:{graph['session_id']}:{chunk['id']}".encode()))
            assert "sha256:" + hashlib.sha256(raw).hexdigest() == blob["id"]
            request = json.loads(raw)
            resource = metadata["resource"]
            endpoint = resource["endpoint"]
            if isinstance(endpoint, str):
                host, port = endpoint.rsplit(":", 1)
                endpoint = {"host": host.strip("[]"), "port": int(port)}
            queries.append(dict(request, case_id=metadata["case_id"], target=endpoint,
                                database=resource.get("database"), username=resource.get("username")))
        cases = sorted(value["cases"], key=lambda case: case["target_request_started_at"])
        root = Path(cases[0]["case_dir"]).parent
        for case in cases:
            for name in ("dependencies.jsonl", "request.json", "expected-response.json"):
                path = Path(case["case_dir"]) / name
                inputs[str(path)] = fingerprint(path)
        workloads.append({"api": root.name, "case_root": str(root),
                          "case_ids": [case["case_id"] for case in cases],
                          "case_clocks": {case["case_id"]: case["target_request_started_at"] for case in cases},
                          "queries": queries})
        print(json.dumps({"api": root.name, "cases": len(cases), "captured_mysql_requests": len(queries),
                          "original_witness_complete": manifest["complete"]}))
    private_write(args.output / "input.json", json.dumps({"key": str(key), "policy": str(snapshot),
                                                         "repeats": args.repeats, "workloads": workloads}))
    private_write(args.output / "immutable-inputs.json", json.dumps(inputs, indent=2))


if __name__ == "__main__":
    main()
