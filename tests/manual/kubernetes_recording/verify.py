#!/usr/bin/env python3
"""Opt-in Docker regression: actual Source startup, interception and failed runs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid


def docker(*args, check=True, timeout=90):
    return subprocess.run(['docker', *args], check=check, text=True, capture_output=True, timeout=timeout)


def verify(binary, image, mode):
    name = 'traffic-e2e-kubernetes-test-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='traffic-e2e-kubernetes-test-') as directory:
        root = Path(directory)
        fixtures = root / 'fixtures'
        fixtures.mkdir(mode=0o755)
        project = fixtures / '.traffic-e2e'
        project.mkdir(mode=0o755)
        data = root / 'data'
        data.mkdir()
        control = root / 'control'
        control.mkdir(mode=0o755)
        (control / 'mode').write_text(mode)
        for script in ('source.py', 'kubectl.py'):
            shutil.copyfile(Path(__file__).with_name(script), fixtures / script)
        (fixtures / 'kubectl').write_text('#!/bin/sh\nexec python3 -S /fixtures/kubectl.py "$@"\n')
        (fixtures / 'kubectl').chmod(0o755)
        (fixtures / 'kubeconfig').write_text('synthetic credentials: no real cluster is contacted\n')
        (project / 'policy.yaml').write_text('format: traffic-policy/v1\nrules: []\n')
        (project / 'project.yaml').write_text('''version: 18
project:
  policy: .traffic-e2e/policy.yaml
recorder:
  kubernetes:
    kubectl_binary: /fixtures/kubectl
    kubeconfig: /fixtures/kubeconfig
  upstream_routes:
    - host: chat-shell.example.svc.cluster.local
      via:
        type: kubernetes_port_forward
        namespace: example
        service: chat-shell
  dns_mock:
    enabled: true
    upstream_dns: 192.0.2.1:53
  tcp_gateway:
    enabled: true
  recording:
    post_ready_settle_ms: 0
''')
        started = False
        try:
            docker('run', '--detach', '--name', name, '--pull=never', '--network=none', '--dns=127.0.0.1',
                   '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--user=0:0', '--env=RUST_LOG=info',
                   '--mount', f'type=bind,src={binary},dst=/usr/local/bin/traffic-e2e,readonly',
                   '--mount', f'type=bind,src={fixtures},dst=/fixtures,readonly',
                   '--mount', f'type=bind,src={control},dst=/control',
                   '--mount', f'type=bind,src={data},dst=/data/traffic-e2e',
                   '--entrypoint=/usr/local/bin/traffic-e2e', image, 'record',
                   '--config', '/fixtures/.traffic-e2e/project.yaml', '--ready-path', '/health',
                   '--startup-timeout-seconds', '15', '--source-workdir', '/app',
                   '--artifact-owner', f'{os.getuid()}:{os.getgid()}',
                   '--', 'python3', '-S', '/fixtures/source.py')
            started = True
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                logs = docker('logs', name).stdout + docker('logs', name).stderr
                running = docker('inspect', '--format={{.State.Running}}', name).stdout.strip() == 'true'
                if not running or 'recording ready; waiting for requests' in logs:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError('recording readiness timed out\n' + logs)
            if mode == 'startup_failure':
                assert not running and 'source started after all forwards' not in logs, logs
                assert docker('wait', name).stdout.strip() != '0', logs
                print(mode + ': Source never started after partial forwarding failure')
                return
            assert running and 'source started after all forwards' in logs, logs
            response = docker('exec', name, 'python3', '-S', '-c',
                              "import urllib.request; print(urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:4080/call',timeout=10).read().decode())")
            assert json.loads(response.stdout) == [
                {'service_port': port, 'host': f'chat-shell.example.svc.cluster.local:{port}'}
                for port in (8100, 9000)
            ], response.stdout
            if mode == 'runtime_failure':
                (control / 'exit').touch()
            else:
                docker('kill', '--signal=TERM', name)
            exit_code = docker('wait', name).stdout.strip()
            logs = docker('logs', name).stdout + docker('logs', name).stderr
            assert (exit_code == '0') == (mode == 'success'), logs
            manifests = list(data.glob('.traffic-e2e/local/artifacts/recordings/*/recording-run.json'))
            assert len(manifests) == 1, manifests
            manifest = json.loads(manifests[0].read_text())
            assert manifest['status'] == ('completed' if mode == 'success' else 'failed'), manifest
            assert manifest['published_cases'] == 1, manifest
            network = json.loads(manifests[0].with_name('recording-network.json').read_text())
            endpoints = {(row['host'], row['port']) for row in network['accessed_endpoints']}
            assert {('chat-shell.example.svc.cluster.local', port) for port in (8100, 9000)} <= endpoints, network
            commands = [json.loads(line)['args'] for line in (control / 'commands.jsonl').read_text().splitlines()]
            assert len(commands) == 3, commands
            print(mode + ': automatic ports, startup barrier, real DNS/TCP capture and run status verified')
        except Exception:
            if started:
                logs = docker('logs', name, check=False)
                print(logs.stdout + logs.stderr)
            raise
        finally:
            if started:
                docker('rm', '--force', name, check=False)
                # The controller can create private CA/runtime files as root.
                # Restore ownership only inside this test's private data mount.
                docker('run', '--rm', '--pull=never', '--network=none', '--user=0:0',
                       '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE',
                       '--mount', f'type=bind,src={data},dst=/test-data',
                       '--entrypoint=chown', image, '--recursive', '--no-dereference',
                       f'{os.getuid()}:{os.getgid()}', '/test-data', check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/traffic-e2e'))
    parser.add_argument('--image', required=True, help='Local recording image containing Python 3, setpriv, ip and iptables')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    for mode in ('success', 'runtime_failure', 'startup_failure'):
        verify(binary, args.image, mode)


if __name__ == '__main__':
    main()
