#!/usr/bin/env python3
"""Dependency-aware HTTP mock for manual readonly recorder verification."""

from __future__ import annotations

import argparse
import http.client
import json
import threading
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


MAX_REQUEST_BODY_BYTES = 1024 * 1024


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host:
        raise argparse.ArgumentTypeError("listen must use HOST:PORT")
    try:
        port = int(port_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("listen port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("listen port must be between 1 and 65535")
    return host, port


def json_body(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")


def decode_response_body(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class DependencyResult:
    method: str
    url: str
    status: int | None
    body: Any
    error: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "body": self.body,
            "error": self.error,
        }


class MockState:
    def __init__(
        self,
        role: str,
        dependency_base: str | None,
        proxy: str,
        timeout_seconds: float,
        event_log: Path | None,
    ) -> None:
        self.role = role
        self.dependency_base = dependency_base.rstrip("/") if dependency_base else None
        proxy_url = urllib.parse.urlsplit(proxy)
        if proxy_url.scheme != "http" or not proxy_url.hostname:
            raise ValueError("--proxy must be an http:// URL")
        self.proxy_host = proxy_url.hostname
        self.proxy_port = proxy_url.port or 80
        self.proxy = proxy
        self.timeout_seconds = timeout_seconds
        self.event_log = event_log
        self.event_log_lock = threading.Lock()

    def accepts_app_requests(self) -> bool:
        return self.role in {"app", "both"}

    def accepts_dependency_requests(self) -> bool:
        return self.role in {"dependency", "both"}

    def record_request(
        self,
        handler: BaseHTTPRequestHandler,
        body: bytes,
        unexpected_write: bool = False,
    ) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "role": self.role,
            "method": handler.command,
            "path": handler.path,
            "client": f"{handler.client_address[0]}:{handler.client_address[1]}",
            "host": handler.headers.get("Host"),
            "scenario_id": handler.headers.get("X-Manual-Scenario-Id"),
            "body_size": len(body),
            "unexpected_write": unexpected_write,
        }
        line = json.dumps(event, ensure_ascii=False, sort_keys=True)
        print(line, flush=True)
        if self.event_log is None:
            return
        with self.event_log_lock:
            self.event_log.parent.mkdir(parents=True, exist_ok=True)
            with self.event_log.open("a", encoding="utf-8") as output:
                output.write(line)
                output.write("\n")

    def call_dependency(
        self,
        method: str,
        path: str,
        scenario_id: str,
        payload: dict[str, Any] | None = None,
    ) -> DependencyResult:
        if self.dependency_base is None:
            return DependencyResult(method, path, None, None, "dependency base is not configured")
        url = f"{self.dependency_base}{path}"
        body = json_body(payload) if payload is not None else None
        headers = {
            "Accept": "application/json",
            "Connection": "close",
            "X-Manual-Scenario-Id": scenario_id,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))

        connection = http.client.HTTPConnection(
            self.proxy_host,
            self.proxy_port,
            timeout=self.timeout_seconds,
        )
        try:
            # Absolute-form forces this request through the recorder proxy even
            # when the machine has NO_PROXY configured for the target host.
            connection.request(method, url, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return DependencyResult(
                method=method,
                url=url,
                status=response.status,
                body=decode_response_body(raw),
                error=None,
            )
        except (OSError, http.client.HTTPException) as error:
            return DependencyResult(method, url, None, None, str(error))
        finally:
            connection.close()


class MockServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], state: MockState) -> None:
        super().__init__(server_address, MockHandler)
        self.state = state


class MockHandler(BaseHTTPRequestHandler):
    server: MockServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format_string: str, *args: object) -> None:
        return

    def read_body(self) -> bytes:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text)
        except ValueError:
            length = 0
        if length < 0 or length > MAX_REQUEST_BODY_BYTES:
            raise ValueError("request body is too large")
        return self.rfile.read(length) if length else b""

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json_body(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.server.state.record_request(self, b"")
        path = urllib.parse.urlsplit(self.path).path
        if path == "/healthz":
            self.send_json(200, {"ok": True, "role": self.server.state.role})
            return
        if path == "/scenario/readonly" and self.server.state.accepts_app_requests():
            self.run_readonly_scenario()
            return
        if path == "/dependency/read" and self.server.state.accepts_dependency_requests():
            self.send_json(
                200,
                {
                    "ok": True,
                    "dependency": "read",
                    "scenario_id": self.headers.get("X-Manual-Scenario-Id"),
                },
            )
            return
        if path == "/fallback-check" and self.server.state.accepts_dependency_requests():
            self.send_json(200, {"ok": True, "route": "fallback", "role": self.server.state.role})
            return
        self.send_json(404, {"ok": False, "error": "route not found", "path": path})

    def do_POST(self) -> None:
        try:
            body = self.read_body()
        except ValueError as error:
            self.send_json(413, {"ok": False, "error": str(error)})
            return
        path = urllib.parse.urlsplit(self.path).path
        unexpected_write = path == "/dependency/write"
        self.server.state.record_request(self, body, unexpected_write=unexpected_write)
        if path == "/dependency/write" and self.server.state.accepts_dependency_requests():
            self.send_json(
                200,
                {
                    "ok": True,
                    "dependency": "write",
                    "unexpected_write_reached_upstream": True,
                    "scenario_id": self.headers.get("X-Manual-Scenario-Id"),
                },
            )
            return
        self.send_json(404, {"ok": False, "error": "route not found", "path": path})

    def run_readonly_scenario(self) -> None:
        scenario_id = str(uuid.uuid4())
        query = urllib.parse.urlencode({"scenario_id": scenario_id})
        read_result = self.server.state.call_dependency(
            "GET",
            f"/dependency/read?{query}",
            scenario_id,
        )
        write_result = self.server.state.call_dependency(
            "POST",
            "/dependency/write",
            scenario_id,
            {"scenario_id": scenario_id, "value": "manual-readonly-test"},
        )
        expectation_met = read_result.status == 200 and write_result.status == 403
        self.send_json(
            200,
            {
                "ok": expectation_met,
                "scenario_id": scenario_id,
                "expected": {
                    "dependency_get_status": 200,
                    "dependency_post_status": 403,
                    "dependency_post_reaches_upstream": False,
                    "case_published": False,
                },
                "actual": {
                    "dependency_get": read_result.as_dict(),
                    "dependency_post": write_result.as_dict(),
                },
            },
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--role",
        choices=("app", "dependency", "both"),
        default="both",
        help="app triggers dependencies; dependency receives them; both enables all routes",
    )
    parser.add_argument("--listen", type=parse_listen, default=parse_listen("127.0.0.1:18085"))
    parser.add_argument("--dependency-base", help="HTTP base URL used by the app role")
    parser.add_argument("--proxy", default="http://127.0.0.1:18081")
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--event-log", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.role in {"app", "both"} and not args.dependency_base:
        raise SystemExit("--dependency-base is required for app and both roles")
    state = MockState(
        role=args.role,
        dependency_base=args.dependency_base,
        proxy=args.proxy,
        timeout_seconds=args.timeout_seconds,
        event_log=args.event_log,
    )
    server = MockServer(args.listen, state)
    print(
        json.dumps(
            {
                "event": "mock_started",
                "role": args.role,
                "listen": f"{args.listen[0]}:{args.listen[1]}",
                "dependency_base": args.dependency_base,
                "proxy": args.proxy,
                "event_log": str(args.event_log) if args.event_log else None,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
