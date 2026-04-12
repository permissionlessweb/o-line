#!/bin/sh
set -e

# Setup root password for SSH
echo "root:internal" | chpasswd

# Configure sshd
cat > /etc/ssh/sshd_config <<EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

# Write HTTP server script
cat > /tmp/httpd.py <<'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'internal-server-ok')
    def log_message(self, *a):
        pass

HTTPServer(('0.0.0.0', 8080), H).serve_forever()
PYEOF

# Start HTTP server in background
python3 /tmp/httpd.py &

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
