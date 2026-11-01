#!/usr/bin/env python3
"""Opt-in regression with real Python Engine.IO, Uvicorn and Recorder capture."""
import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def docker(*args, check=True, timeout=60):
    result = subprocess.run(['docker', *args], text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'docker {args[0]} failed:\n{result.stdout}{result.stderr}')
    return result


CLIENT = '''
import asyncio, json, socket, struct, sys
import websockets

async def main():
    mode = sys.argv[1]
    async with websockets.connect(
        'ws://127.0.0.1:4080/socket.io/?EIO=4&transport=websocket',
        close_timeout=2,
    ) as ws:
        assert (await ws.recv()).startswith('0')
        await ws.send('40')
        assert (await ws.recv()).startswith('40')
        await ws.send('421["ask",1]')
        assert await ws.recv() == '431[1]'
        if mode == 'engineio':
            await ws.send('1')
            await ws.wait_closed()
        elif mode in ('eof', 'reset', 'partial_frame'):
            if mode == 'reset':
                ws.transport.get_extra_info('socket').setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                ws.transport.abort()
            else:
                if mode == 'partial_frame':
                    ws.transport.write(bytes([0x81, 0xfe, 0x00]))
                ws.transport.write_eof()
            await ws.wait_closed()
        else:
            await ws.close(code=int(mode))
            assert ws.close_code == int(mode), ('client close echo', ws.close_code)

asyncio.run(main())
'''

SNAPSHOT = '''
import json
from pathlib import Path
root = Path('/data/traffic-e2e/.traffic-e2e/local/artifacts/recordings')
print(json.dumps({
    'published': len(list(root.glob('*/apis/*/*/expected-response.json'))),
    'failed': len(list(root.glob('*/failed/*/*/recording-error.json'))),
}))
'''



# This isolated fixture produces twelve small GET exchanges. Keep accidental
# input expansion explicit instead of materializing an arbitrary recording.
MAX_METADATA_BYTES = 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_CASE_RECORDS = 64


def file_stamp(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def sha256_value(value):
    assert isinstance(value, str), 'missing sealed content identity'
    digest = value.removeprefix('sha256:').lower()
    assert len(digest) == 64 and all(ch in '0123456789abcdef' for ch in digest), 'invalid SHA256 identity'
    return digest


def bounded_json(path):
    assert path.stat().st_size <= MAX_METADATA_BYTES, f'fixture metadata exceeds its bound: {path}'
    with path.open('rb') as source:
        raw = source.read(MAX_METADATA_BYTES + 1)
    assert len(raw) <= MAX_METADATA_BYTES
    return json.loads(raw)


def authenticate_file(path, identity, limit, cache):
    before = file_stamp(path)
    assert 0 <= before[2] <= limit, f'fixture file exceeds its bound: {path}'
    assert identity['length'] == before[2], f'sealed file length changed: {path}'
    expected = sha256_value(identity['sha256'])
    if cache.get(path) == (before, expected):
        return before
    digest = hashlib.sha256()
    total = 0
    with path.open('rb') as source:
        while block := source.read(64 * 1024):
            total += len(block)
            assert total <= limit, f'fixture file grew beyond its bound: {path}'
            digest.update(block)
    assert file_stamp(path) == before, f'fixture file changed during authentication: {path}'
    assert total == before[2] and digest.hexdigest() == expected, f'sealed file content changed: {path}'
    cache[path] = (before, expected)
    return before


def check_case_owner(record, case_id, required):
    capture = record.get('capture')
    assert isinstance(record.get('event_type'), str), 'semantic records must remain typed; protected payloads require the engine evidence interface'
    if capture is None:
        assert not required, 'v3 semantic occurrence has no capture identity'
        return
    owner = capture['attribution']
    assert owner['kind'] == 'case' and owner['origin_case_id'] == case_id, 'dependency escaped its original Case owner'


def case_dependencies(case, recording, cache):
    """Read only original semantic records selected by the authenticated Case view."""
    recording = recording.resolve(strict=True)
    case_id = str(uuid.UUID(case.name))
    manifest_path = recording / 'dependency-manifest.json'
    scope_path = case / 'dependency-scope.json'
    if not scope_path.exists():
        assert not manifest_path.exists(), 'v3 recording is missing its Case scope; do not fall back to another view'
        legacy = case / 'dependencies.jsonl'
        stamp = file_stamp(legacy)
        assert stamp[2] <= MAX_LEDGER_BYTES, 'legacy fixture exceeds its bound'
        with legacy.open('rb') as source:
            count = 0
            while raw := source.readline(MAX_RECORD_BYTES + 1):
                assert len(raw) <= MAX_RECORD_BYTES, 'legacy record exceeds its bound'
                if not raw.strip():
                    continue
                count += 1
                assert count <= MAX_CASE_RECORDS, 'legacy Case exceeds its finite fixture inventory'
                record = json.loads(raw)
                check_case_owner(record, case_id, required=False)
                yield record
        assert file_stamp(legacy) == stamp, 'legacy dependency file changed during read'
        return
    manifest = bounded_json(manifest_path)
    assert manifest['schema'] == 'traffic-recording/v3' and manifest['sealed'], 'current recording must be sealed'
    assert manifest['run_id'] == recording.name, 'sealed run identity changed'
    files = {entry['path']: entry for entry in manifest['files']}
    assert len(files) == len(manifest['files']), 'duplicate sealed file identities'
    relative_scope = scope_path.relative_to(recording).as_posix()
    authenticate_file(scope_path, files[relative_scope], MAX_METADATA_BYTES, cache)
    scope = bounded_json(scope_path)
    assert scope['schema'] == 'traffic-dependency-scope/v3'
    assert scope['scope'] == {'kind': 'case', 'case_id': case_id}, 'foreign Case scope'
    relative_run = Path(scope['run_relpath'])
    assert not relative_run.is_absolute() and (case / relative_run).resolve(strict=True) == recording, 'Case scope escapes the selected run'
    ledger = (recording / 'dependencies.jsonl').resolve(strict=True)
    assert ledger.parent == recording, 'central ledger escapes the selected run'
    stamp = authenticate_file(ledger, files['dependencies.jsonl'], MAX_LEDGER_BYTES, cache)
    locations = scope['locations']
    assert len(locations) <= MAX_CASE_RECORDS, 'Case scope exceeds its finite fixture inventory'
    previous_end = previous_line = 0
    with ledger.open('rb') as source:
        for location in locations:
            offset, length, line = location['offset'], location['length'], location['line']
            assert all(type(value) is int for value in (offset, length, line))
            assert offset >= previous_end and 0 < length <= MAX_RECORD_BYTES and offset + length <= stamp[2], 'invalid or overlapping record range'
            assert line > previous_line, 'unordered physical Source records'
            source.seek(offset)
            raw = source.read(length)
            assert len(raw) == length and raw.endswith(b'\n') and raw.count(b'\n') == 1, 'incomplete central JSONL record'
            assert hashlib.sha256(raw).hexdigest() == sha256_value(location['sha256']), 'Case reference content hash differs from original ledger'
            record = json.loads(raw)
            check_case_owner(record, case_id, required=True)
            capture = record['capture']
            assert capture['exchange_id'] == location['exchange_id'] and capture['effect_index'] == location['effect_index'], 'Case reference changed physical occurrence identity'
            previous_end, previous_line = offset + length, line
            yield record
    assert file_stamp(ledger) == stamp, 'central ledger changed during scoped read'


def captured_bytes(body):
    # Semantic Redis BodyCapture is explicit base64. Do not decrypt or reinterpret
    # protected envelopes, truncated previews, or protocol debug records.
    assert body.get('truncated') is False, 'truncated dependency body'
    assert isinstance(body.get('data'), str), 'protected dependency body requires engine evidence access'
    if body['encoding'] == 'base64':
        raw = base64.b64decode(body['data'], validate=True)
    else:
        assert body['encoding'] == 'utf8', 'unsupported dependency body encoding; use the engine evidence interface'
        raw = body['data'].encode()
    assert len(raw) == body['stored_len'] == body['original_len'], 'incomplete dependency body'
    return raw


def assert_artifact_owners(recording, expected_uid=None, expected_gid=None):
    """Inspect completed recording metadata before the cleanup-only chown runs."""
    expected = (os.getuid() if expected_uid is None else expected_uid,
                os.getgid() if expected_gid is None else expected_gid)
    recording = recording.resolve(strict=True)
    paths = {recording}
    manifest_path = recording / 'dependency-manifest.json'
    for path in [recording, *([manifest_path] if manifest_path.exists() else [])]:
        stat = path.lstat()
        assert (stat.st_uid, stat.st_gid) == expected, f'wrong recording owner before cleanup: {path} {(stat.st_uid, stat.st_gid)} != {expected}'
    if manifest_path.exists():
        for entry in bounded_json(manifest_path)['files']:
            relative = Path(entry['path'])
            assert not relative.is_absolute() and '..' not in relative.parts, 'sealed recording path escapes its run'
            path = recording / relative
            assert path.resolve(strict=True).is_relative_to(recording), 'sealed file escapes its recording'
            paths.add(path)
    excluded = {'controller-ca', '.controller-ca', 'secrets', '.secrets'}
    derived_names = {'.dependency-index.json', '.global-replay-index.json', '.mysql-transactions.json'}
    derived = []
    for base, directories, names in os.walk(recording, followlinks=False):
        directories[:] = [name for name in directories if name not in excluded]
        paths.add(Path(base))
        for name in names:
            if name.endswith(('.json', '.jsonl', '.yaml', '.yml')) or name in derived_names:
                path = Path(base) / name
                paths.add(path)
                if name in derived_names:
                    derived.append(path)
        assert len(paths) <= 4096, 'recording ownership check exceeds this finite fixture'
    assert derived, 'fixture must include derived index fragments to exercise artifact-owner publication'
    for path in sorted(paths):
        stat = path.lstat()
        actual = (stat.st_uid, stat.st_gid)
        assert actual == expected, f'wrong recording artifact owner before cleanup: {path.relative_to(recording)} {actual} != {expected}'
    return len(derived)


def verify(binary, image):
    name = 'traffic-e2e-asgi-close-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='traffic-e2e-asgi-close-') as directory:
        root = Path(directory)
        fixtures = root / 'fixtures'
        fixtures.mkdir(mode=0o755)
        project = fixtures / '.traffic-e2e'
        project.mkdir(mode=0o755)
        data = root / 'data'
        data.mkdir()
        shutil.copyfile(Path(__file__).with_name('source.py'), fixtures / 'source.py')
        (project / 'policy.yaml').write_text('format: traffic-policy/v3\nrules: []\n')
        (project / 'project.yaml').write_text('''version: 18
project:
  policy: .traffic-e2e/policy.yaml
recorder:
  dns_mock:
    enabled: true
    upstream_dns: 192.0.2.1:53
    hosts:
      redis.close.test: [127.0.0.1]
  tcp_gateway:
    enabled: true
  http_gateway:
    record_streaming: true
    request_timeout_ms: 5000
    interaction:
      business_idle_ms: 2000
      cleanup_timeout_ms: 5000
    rules:
      - name: socketio
        methods: [GET, POST]
        path_prefixes: [/socket.io/]
  recording:
    post_ready_settle_ms: 0
    case_dependency_post_response_window_ms: 0
''')
        started = False
        try:
            mounts = ['--mount', f'type=bind,src={fixtures},dst=/fixtures,readonly',
                      '--mount', f'type=bind,src={data},dst=/data/traffic-e2e']
            if binary is not None:
                mounts += ['--mount', f'type=bind,src={binary},dst=/usr/local/bin/traffic-e2e,readonly']
            docker('run', '--detach', '--name', name, '--pull=never', '--network=none',
                   '--dns=127.0.0.1', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
                   '--user=0:0', '--env=RUST_LOG=info', *mounts,
                   '--entrypoint=/usr/local/bin/traffic-e2e', image, 'record',
                   '--config', '/fixtures/.traffic-e2e/project.yaml',
                   '--policy', '/fixtures/.traffic-e2e/policy.yaml', '--ready-path', '/health',
                   '--startup-timeout-seconds', '15', '--source-workdir', '/app',
                   '--artifact-owner', f'{os.getuid()}:{os.getgid()}',
                   '--', 'python3', '/fixtures/source.py')
            started = True
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                logs = docker('logs', name)
                if 'recording ready; waiting for requests' in logs.stdout + logs.stderr:
                    break
                assert docker('inspect', '--format={{.State.Running}}', name).stdout.strip() == 'true'
                time.sleep(0.1)
            else:
                raise AssertionError('recording readiness timed out')
            modes = ['1000', 'eof', '1001', 'reset', 'engineio', 'partial_frame'] * 2
            failed_modes = {'partial_frame'}
            published_count = failed_count = 0
            for turn, mode in enumerate(modes, start=1):
                docker('exec', name, 'python3', '-c', CLIENT, mode, timeout=15)
                if mode in failed_modes:
                    failed_count += 1
                else:
                    published_count += 1
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    assert docker('inspect', '--format={{.State.Running}}', name).stdout.strip() == 'true', 'Source isolation stopped recording'
                    snapshot = json.loads(docker('exec', name, 'python3', '-c', SNAPSHOT).stdout)
                    if snapshot == {'published': published_count, 'failed': failed_count}:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError(f'case {turn} did not publish')
            docker('kill', '--signal=TERM', name)
            # The record CLI reports retained failed cases on final shutdown;
            # continued recording must not turn them into a successful batch.
            assert docker('wait', name).stdout.strip() == ('1' if failed_count else '0')
            manifests = list(data.glob('.traffic-e2e/local/artifacts/recordings/*/recording-run.json'))
            assert len(manifests) == 1, manifests
            manifest = json.loads(manifests[0].read_text())
            assert manifest['status'] == 'completed' and manifest['failed_cases'] == failed_count, manifest
            assert manifest['published_cases'] == published_count, manifest
            recording = manifests[0].parent
            ledger_cache = {}
            owned_indexes = assert_artifact_owners(recording)
            final_logs = docker('logs', name)
            assert 'failed to finalize recording run' not in final_logs.stdout + final_logs.stderr, 'recording finalization failed independently of retained partial-frame cases'
            cases = list(manifests[0].parent.glob('apis/*/*')) + list(manifests[0].parent.glob('failed/*/*'))
            cases.sort(key=lambda case: json.loads((case / ('request.json.invalid' if (case / 'recording-error.json').exists() else 'request.json')).read_text())['timestamp'])
            assert len(cases) == len(modes), cases
            for turn, (case, mode) in enumerate(zip(cases, modes), start=1):
                failed = mode in failed_modes
                request = json.loads((case / ('request.json.invalid' if failed else 'request.json')).read_text())
                expected = json.loads((case / ('expected-response.json.invalid' if failed else 'expected-response.json')).read_text())
                assert expected['interaction']['end']['clean'] == (not failed), expected['interaction']['end']
                if failed:
                    error = json.loads((case / 'recording-error.json').read_text())
                    assert error['reason'] == 'interaction_client_transport_lost', error
                    assert expected['interaction']['end']['reason'] == 'transport_error'
                    assert expected['interaction']['end'].get('close') is None
                    assert not (case / 'expected-response.json').exists()
                elif mode in ('eof', 'reset'):
                    terminal = request['interaction']['actions'][-1]
                    assert terminal['action'] == {'kind': 'transport_end', 'end': mode}, terminal
                    assert sum(action['action']['kind'] == 'transport_end' for action in request['interaction']['actions']) == 1
                    assert all(action['action']['kind'] != 'close' for action in request['interaction']['actions']), 'client TCP end must not invent a WebSocket CLOSE'
                    assert terminal['after'] == [] and not terminal['compressible_gap'], terminal
                    assert terminal.get('ack_ref') is None and terminal.get('gap_start_ms') is None
                    assert request['interaction']['socket_io_heartbeat'] == {'responses': []}
                    assert expected['interaction']['end']['reason'] == 'client_transport_end'
                    assert expected['interaction']['end'].get('close') is None
                    assert expected['interaction']['end']['offset_ms'] >= terminal['offset_ms'] + 150
                    assert not (case / 'recording-error.json').exists()
                elif mode != 'engineio':
                    assert expected['interaction']['end']['close']['code'] == int(mode)
                exchanges = [row for row in case_dependencies(case, recording, ledger_cache) if row['event_type'] == 'redis_exchange']
                assert len(exchanges) == 1, exchanges
                exchange = exchanges[0]
                assert exchange['command'] == 'GET' and len(exchange['args']) == 1
                assert captured_bytes(exchange['args'][0]) == f'late-{turn}'.encode()
                assert captured_bytes(exchange['response']) == b'$2\r\nok\r\n'
                assert exchange.get('outcome', 'response') == 'response' and exchange['replay_safe']
                dependency_started = datetime.fromisoformat(exchange['request_started_at'].replace('Z', '+00:00'))
                admitted = datetime.fromisoformat(request['timestamp'].replace('Z', '+00:00'))
                final_input = request['interaction']['actions'][-1]['offset_ms']
                assert (dependency_started - admitted).total_seconds() * 1000 >= final_input + 150, 'disconnect dependency must start after the delayed callback, inside its original Case'
            versions = docker('run', '--rm', '--pull=never', '--network=none', '--read-only',
                              '--entrypoint=python3', image, '-c',
                              "from importlib.metadata import version; print({k:version(k) for k in ['python-engineio','python-socketio','uvicorn']})").stdout.strip()
            print(f'{len(modes)} cases verified: {published_count} clean WS/Engine.IO/TCP ends, {failed_count} retained partial-frame failures, delayed Redis ownership, Source reuse, {owned_indexes} derived indexes with artifact-owner UID/GID and truthful final failed-case status; {versions}')
        except Exception:
            if started:
                logs = docker('logs', name, check=False)
                print(logs.stdout + logs.stderr)
            raise
        finally:
            if started:
                docker('rm', '--force', name, check=False)
                docker('run', '--rm', '--pull=never', '--network=none', '--user=0:0',
                       '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE',
                       '--mount', f'type=bind,src={data},dst=/test-data',
                       '--entrypoint=chown', image, '--recursive', '--no-dereference',
                       f'{os.getuid()}:{os.getgid()}', '/test-data', check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, help='Mount a replacement binary; omit to test the image itself')
    parser.add_argument('--image', required=True, help='Local recording image containing Python Socket.IO, Uvicorn, websockets, setpriv, ip and iptables')
    args = parser.parse_args()
    verify(args.binary.resolve(strict=True) if args.binary else None, args.image)
