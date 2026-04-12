"""Mock pfSense REST API for integration testing.

Provides minimal status and config endpoints. Actual firewall rules
and webConfigurator simulation will be added in Phase 2.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler


class PfSenseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/status":
            self._json_response({"status": "ok", "version": "mock-2.7.2"})
        elif self.path == "/api/v1/system/info":
            self._json_response({
                "hostname": "pfsense-mock",
                "platform": "pfSense",
                "version": "2.7.2-RELEASE",
            })
        else:
            self.send_response(404)
            self.end_headers()

    def _json_response(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # suppress request logs


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8880), PfSenseHandler)
    print("[mock-api] Listening on :8880")
    server.serve_forever()
