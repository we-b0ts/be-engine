"""Source verifies the preparation barrier, then exercises real fake-DNS capture."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

for port in (8100, 9000):
    assert Path(f'/control/listen-{port}.json').is_file(), 'Source started before forwarding readiness'
print('source started after all forwards', flush=True)
client = build_opener(ProxyHandler({}))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            body = b'{}'
        else:
            results = []
            for port in (8100, 9000):
                with client.open(f'http://chat-shell.example.svc.cluster.local:{port}/dependency', timeout=5) as response:
                    results.append(json.load(response))
            body = json.dumps(results).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


HTTPServer(('127.0.0.1', 8080), Handler).serve_forever()
