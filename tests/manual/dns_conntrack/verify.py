#!/usr/bin/env python3
"""Opt-in DNS interception regression in a disposable Linux network namespace."""

import argparse
import ipaddress
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading


TRAFFIC_UID = 998
SOURCE_IP = "127.0.0.1"
REAL_DNS = ("127.0.0.2", 53)
FIRST_MOCK = ("127.0.0.153", 4053)
SECOND_MOCK = ("127.0.0.154", 4054)
WILDCARD_MOCK = ("0.0.0.0", 4055)
REAL_ANSWER = "192.0.2.11"
FIRST_ANSWER = "198.19.0.99"
SECOND_ANSWER = "198.19.0.100"
SCRIPT = Path(__file__).resolve()


def command(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15, **kwargs)
    if result.returncode:
        displayed_args = [arg if len(str(arg)) < 256 else "<inline Python client>" for arg in args]
        raise AssertionError(
            f"command failed ({result.returncode}): {displayed_args!r}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def read_exact(stream, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.recv(size - len(chunks))
        if not chunk:
            raise AssertionError("DNS TCP connection closed before the full message")
        chunks.extend(chunk)
    return bytes(chunks)


def dns_query(protocol, source_port):
    question = b"\x05probe\x07invalid\x00\x00\x01\x00\x01"
    request = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as client:
        client.settimeout(3)
        if protocol == "tcp":
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.bind((SOURCE_IP, source_port))
        # Connected UDP also checks reverse NAT: a reply directly from the mock
        # listener is not accepted as a reply from the original resolver.
        client.connect(REAL_DNS)
        if protocol == "udp":
            client.send(request)
            response = client.recv(2048)
        else:
            client.sendall(struct.pack("!H", len(request)) + request)
            length = struct.unpack("!H", read_exact(client, 2))[0]
            response = read_exact(client, length)
    if len(response) < 16 or response[:2] != request[:2]:
        raise AssertionError("invalid DNS response")
    return str(ipaddress.IPv4Address(response[-4:]))


class DnsServer:
    def __init__(self, listener, answer):
        self.answer = ipaddress.IPv4Address(answer).packed
        self.stopping = threading.Event()
        self.sockets = []
        self.threads = []
        for protocol, kind in [("udp", socket.SOCK_DGRAM), ("tcp", socket.SOCK_STREAM)]:
            server = socket.socket(socket.AF_INET, kind)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(listener)
            server.settimeout(0.1)
            if protocol == "tcp":
                server.listen(8)
            self.sockets.append(server)
            thread = threading.Thread(target=self.serve, args=(server, protocol), daemon=True)
            thread.start()
            self.threads.append(thread)

    def reply(self, request):
        if len(request) < 12:
            raise AssertionError("truncated DNS request")
        header = request[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + self.answer
        return header + request[12:] + answer

    def serve(self, server, protocol):
        while not self.stopping.is_set():
            try:
                if protocol == "udp":
                    request, peer = server.recvfrom(2048)
                    server.sendto(self.reply(request), peer)
                else:
                    stream, _ = server.accept()
                    with stream:
                        stream.settimeout(3)
                        length = struct.unpack("!H", read_exact(stream, 2))[0]
                        response = self.reply(read_exact(stream, length))
                        stream.sendall(struct.pack("!H", len(response)) + response)
            except socket.timeout:
                continue
            except OSError:
                if not self.stopping.is_set():
                    raise

    def close(self):
        self.stopping.set()
        for thread in self.threads:
            thread.join(timeout=4)
        for server in self.sockets:
            server.close()


def query_as(uid, protocol, source_port, expected):
    # The checkout may be private to its owner. Pass this small client over
    # argv instead of granting UID 998 access to the repository or interpreter.
    client_code = "\n".join([
        "import ipaddress, json, socket, struct, sys",
        f"REAL_DNS = {REAL_DNS!r}",
        f"SOURCE_IP = {SOURCE_IP!r}",
        inspect.getsource(read_exact),
        inspect.getsource(dns_query),
        "print(json.dumps({'answer': dns_query(sys.argv[1], int(sys.argv[2]))}))",
    ])
    output = command(
        ["/usr/bin/python3", "-c", client_code, protocol, str(source_port)],
        user=uid,
        group=uid,
        extra_groups=[],
    )
    actual = json.loads(output)["answer"]
    if actual != expected:
        raise AssertionError(
            f"UID {uid}, {protocol}, source port {source_port}: "
            f"expected {expected}, received {actual}"
        )


def firewall_state():
    return {
        table: command(["iptables", "-t", table, "-S"])
        for table in ["raw", "nat"]
    }


def interception(binary, operation, listener):
    command([
        str(binary), "diagnose", "interception", "dns", operation,
        "--dns-ip", listener[0], "--dns-port", str(listener[1]),
    ])


def udp_flows(source_port):
    output = command([
        "conntrack", "-L", "-p", "udp", "--orig-src", SOURCE_IP,
        "--orig-dst", REAL_DNS[0], "--sport", str(source_port), "--dport", "53", "-o", "id",
    ])
    return [line for line in output.splitlines() if line.startswith("udp")]


def default_flow_id(flows):
    default = [line for line in flows if "zone=" not in line or "zone=0 " in line]
    if len(default) != 1 or not (match := re.search(r"\bid=(\d+)\b", default[0])):
        raise AssertionError(f"expected one default-zone flow with a conntrack ID: {flows}")
    return match.group(1)


def verify_inside_namespace(binary, host_namespace, routed):
    global SOURCE_IP, REAL_DNS
    current_namespace = os.stat("/proc/self/ns/net").st_ino
    initial_namespace = os.stat("/proc/1/ns/net").st_ino
    if os.geteuid() != 0 or current_namespace in (host_namespace, initial_namespace):
        raise AssertionError("refusing firewall commands outside an isolated root network namespace")
    for executable in ["ip", "iptables", "conntrack"]:
        if not shutil.which(executable):
            raise AssertionError(f"required executable is missing: {executable}")
    command(["ip", "link", "set", "lo", "up"])
    if routed:
        SOURCE_IP = "192.0.2.10"
        REAL_DNS = ("192.0.2.53", 53)
        command(["ip", "link", "add", "dns-regression", "type", "dummy"])
        command(["ip", "address", "add", f"{SOURCE_IP}/24", "dev", "dns-regression"])
        command(["ip", "address", "add", f"{REAL_DNS[0]}/24", "dev", "dns-regression"])
        command(["ip", "link", "set", "dns-regression", "up"])
    print(f"DNS source {SOURCE_IP} -> resolver {REAL_DNS[0]} (isolated namespace)", flush=True)
    baseline = firewall_state()
    if any("-A " in state or "TRP_DNS" in state for state in baseline.values()):
        raise AssertionError("new network namespace must start with empty raw/nat rules")
    # A fresh namespace has no conntrack consumer before DNS up. This benign
    # ACCEPT rule enables tracking so the pre-existing root flow is genuine.
    tracking_rule = [
        "OUTPUT", "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT",
    ]
    command(["iptables", "-A", *tracking_rule])
    servers = [
        DnsServer(REAL_DNS, REAL_ANSWER),
        DnsServer(FIRST_MOCK, FIRST_ANSWER),
        DnsServer(SECOND_MOCK, SECOND_ANSWER),
    ]
    try:
        legacy_port = 43101
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        if len(udp_flows(legacy_port)) != 1:
            raise AssertionError("root query did not establish the legacy UDP conntrack tuple")
        legacy_id = default_flow_id(udp_flows(legacy_port))

        interception(binary, "up", FIRST_MOCK)
        first_rules = firewall_state()
        interception(binary, "up", FIRST_MOCK)
        if firewall_state() != first_rules:
            raise AssertionError("repeated DNS up changed rules or installed duplicates")
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        query_as(TRAFFIC_UID, "udp", legacy_port, FIRST_ANSWER)
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        flows = udp_flows(legacy_port)
        zones = {
            int(match.group(1)) if (match := re.search(r"\bzone=(\d+)\b", line)) else 0
            for line in flows
        }
        if len(flows) != 2 or 0 not in zones or not any(zones) or default_flow_id(flows) != legacy_id:
            raise AssertionError(f"same UDP tuple did not retain distinct root/traffic zones: {flows}")
        print("PASS: old root UDP conntrack tuple cannot bypass UID 998 capture", flush=True)

        interception(binary, "up", FIRST_MOCK)
        query_as(TRAFFIC_UID, "udp", legacy_port, FIRST_ANSWER)
        query_as(0, "udp", legacy_port, REAL_ANSWER)

        query_as(TRAFFIC_UID, "tcp", 43102, FIRST_ANSWER)
        query_as(0, "tcp", 43103, REAL_ANSWER)
        print("PASS: UDP and TCP capture preserve the root resolver path", flush=True)

        interception(binary, "up", SECOND_MOCK)
        switched_rules = firewall_state()
        if any(FIRST_MOCK[0] in rules for rules in switched_rules.values()):
            raise AssertionError("listener change retained rules for the old listener IP")
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        query_as(TRAFFIC_UID, "udp", legacy_port, SECOND_ANSWER)
        query_as(TRAFFIC_UID, "tcp", 43105, SECOND_ANSWER)
        print("PASS: changing listener IP and port replaces the existing captured tuple", flush=True)

        interception(binary, "down", SECOND_MOCK)
        interception(binary, "down", SECOND_MOCK)
        if firewall_state() != baseline:
            raise AssertionError("DNS down did not remove all installed raw/nat rules and chains")
        if len(udp_flows(legacy_port)) != 1 or default_flow_id(udp_flows(legacy_port)) != legacy_id:
            raise AssertionError("DNS down must remove captured flows and retain the root flow")
        query_as(TRAFFIC_UID, "udp", legacy_port, REAL_ANSWER)
        query_as(TRAFFIC_UID, "tcp", 43107, REAL_ANSWER)
        print("PASS: repeated DNS down restores uncaptured traffic and removes all rules", flush=True)

        interception(binary, "up", FIRST_MOCK)
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        query_as(TRAFFIC_UID, "udp", legacy_port, FIRST_ANSWER)
        established_rules = firewall_state()
        rejected = subprocess.run([
            str(binary), "diagnose", "interception", "dns", "up",
            "--dns-ip", WILDCARD_MOCK[0], "--dns-port", str(WILDCARD_MOCK[1]),
        ], capture_output=True, text=True, timeout=15)
        if rejected.returncode == 0 or firewall_state() != established_rules:
            raise AssertionError("wildcard DNS up must be rejected before changing existing rules")
        if len(udp_flows(legacy_port)) != 2 or default_flow_id(udp_flows(legacy_port)) != legacy_id:
            raise AssertionError("wildcard rejection changed existing conntrack state")
        query_as(TRAFFIC_UID, "udp", legacy_port, FIRST_ANSWER)
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        print("PASS: wildcard listener is rejected without changing established capture", flush=True)
        interception(binary, "down", FIRST_MOCK)
        if firewall_state() != baseline:
            raise AssertionError("up/down cycle left stale rules")
        print("PASS: a fresh up/down cycle remains isolated and cleans up", flush=True)

        with open("/dev/full", "wb") as full:
            result = subprocess.run([
                str(binary), "diagnose", "interception", "dns", "up",
                "--dns-ip", FIRST_MOCK[0], "--dns-port", str(FIRST_MOCK[1]),
            ], stdout=full, stderr=subprocess.PIPE, text=True, timeout=15)
        if result.returncode == 0:
            raise AssertionError("DNS up did not report its /dev/full output failure")
        if (
            firewall_state() != baseline or len(udp_flows(legacy_port)) != 1
            or default_flow_id(udp_flows(legacy_port)) != legacy_id
        ):
            raise AssertionError("failed DNS up did not roll back rules/zone while retaining root's flow")
        query_as(0, "udp", legacy_port, REAL_ANSWER)
        print("PASS: a late DNS up failure rolls back rules and captured flows", flush=True)
    finally:
        interception(binary, "down", SECOND_MOCK)
        for server in servers:
            server.close()
        command(["iptables", "-D", *tracking_rule])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/traffic-e2e"))
    parser.add_argument("--inside-netns", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--routed", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"traffic-e2e binary is not executable: {binary}")
    if args.inside_netns is not None:
        verify_inside_namespace(binary, args.inside_netns, args.routed)
        return
    host_namespace = os.stat("/proc/self/ns/net").st_ino
    for routed in ([True] if args.routed else [False, True]):
        invocation = [
            "unshare", "--net", "--", sys.executable, str(SCRIPT),
            "--binary", str(binary), "--inside-netns", str(host_namespace),
        ]
        if routed:
            invocation.append("--routed")
        if os.geteuid() != 0:
            invocation = ["sudo", "-n", *invocation]
        result = subprocess.run(invocation, check=False)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
