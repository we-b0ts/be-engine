"""Synthetic kubectl contract for testing the real recorder in isolation."""
import json
import os
from pathlib import Path
import socket
import sys
import time

control = Path('/control')
mode = (control / 'mode').read_text()
with (control / 'commands.jsonl').open('a') as output:
    output.write(json.dumps({'args': sys.argv[1:], 'pid': os.getpid()}) + '\n')
if 'get' in sys.argv:
    print(json.dumps({
        'kind': 'Service', 'metadata': {'namespace': 'example', 'name': 'chat-shell'},
        'spec': {'selector': {'app': 'chat-shell'}, 'ports': [
            {'port': port, 'targetPort': port + 1, 'protocol': 'TCP'}
            for port in (8100, 9000)
        ]},
    }))
    sys.exit(0)

port = int(sys.argv[-1][1:])
if port == 9000:
    time.sleep(0.2)
    if mode == 'startup_failure':
        print('synthetic kubectl startup failure', file=sys.stderr)
        sys.exit(3)
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen()
listener.settimeout(0.05)
address = listener.getsockname()
(control / f'listen-{port}.json').write_text(json.dumps(address))
print(f'Forwarding from 127.0.0.1:{address[1]} -> {port + 1}', flush=True)
while not (control / 'exit').exists():
    try:
        connection, _ = listener.accept()
    except socket.timeout:
        continue
    with connection:
        connection.settimeout(3)
        request = b''
        while b'\r\n\r\n' not in request:
            chunk = connection.recv(4096)
            if not chunk:
                break
            request += chunk
        if not request:
            continue
        host = next(line.split(b':', 1)[1].strip().decode() for line in request.split(b'\r\n') if line.lower().startswith(b'host:'))
        body = json.dumps({'service_port': port, 'host': host}).encode()
        connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
sys.exit(7)
