#!/bin/sh
set -e

# Setup root password for SSH
echo "root:client" | chpasswd

# Configure sshd
cat > /etc/ssh/sshd_config <<EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
EOF

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
