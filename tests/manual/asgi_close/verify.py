#!/usr/bin/env python3
"""Opt-in regression with real Python Engine.IO, Uvicorn and Recorder capture."""
import argparse
import base64
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
            failed_modes = {'eof', 'reset', 'partial_frame'}
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
            cases = list(manifests[0].parent.glob('apis/*/*')) + list(manifests[0].parent.glob('failed/*/*'))
            cases.sort(key=lambda case: json.loads((case / ('request.json.invalid' if (case / 'recording-error.json').exists() else 'request.json')).read_text())['timestamp'])
            assert len(cases) == len(modes), cases
            for turn, (case, mode) in enumerate(zip(cases, modes), start=1):
                failed = mode in failed_modes
                expected = json.loads((case / ('expected-response.json.invalid' if failed else 'expected-response.json')).read_text())
                assert expected['interaction']['end']['clean'] == (not failed), expected['interaction']['end']
                if failed:
                    error = json.loads((case / 'recording-error.json').read_text())
                    assert error['reason'] == 'interaction_client_transport_lost', error
                    assert expected['interaction']['end']['reason'] == 'transport_error'
                    assert expected['interaction']['end'].get('close') is None
                    assert not (case / 'expected-response.json').exists()
                elif mode != 'engineio':
                    assert expected['interaction']['end']['close']['code'] == int(mode)
                exchanges = [row for row in map(json.loads, (case / 'dependencies.jsonl').read_text().splitlines()) if row['event_type'] == 'redis_exchange']
                assert len(exchanges) == 1, exchanges
                assert base64.b64decode(exchanges[0]['args'][0]['data']) == f'late-{turn}'.encode()
            versions = docker('run', '--rm', '--pull=never', '--network=none', '--read-only',
                              '--entrypoint=python3', image, '-c',
                              "from importlib.metadata import version; print({k:version(k) for k in ['python-engineio','python-socketio','uvicorn']})").stdout.strip()
            print(f'{len(modes)} cases verified: {published_count} clean WS/Engine.IO closes, {failed_count} retained EOF/reset/partial-frame failures, delayed Redis ownership, Source reuse and truthful final failed-case status; {versions}')
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
