#!/bin/bash
set -e

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-pfsense}"

# Create admin user with password
if ! id "$ADMIN_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$ADMIN_USER"
fi
echo "${ADMIN_USER}:${ADMIN_PASS}" | chpasswd

# Set root password (same as admin pass) for VPN SSH operations
echo "root:${ADMIN_PASS}" | chpasswd

# Configure sshd for password auth
cat > /etc/ssh/sshd_config <<EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Generate host keys if missing
ssh-keygen -A

# ── Mock pfSense environment ────────────────────────────────────────────────

# Install mock pfSsh.php, easyrule, and firewall rules script
mkdir -p /usr/local/sbin /conf /var/log
cp /opt/mock/pfSsh.php /usr/local/sbin/pfSsh.php
cp /opt/mock/easyrule /usr/local/sbin/easyrule
cp /opt/mock/apply_firewall_rules.sh /usr/local/sbin/apply_firewall_rules.sh
chmod +x /usr/local/sbin/pfSsh.php /usr/local/sbin/easyrule /usr/local/sbin/apply_firewall_rules.sh

# Allow admin user to apply firewall rules via sudo (iptables requires root)
echo "$ADMIN_USER ALL=(root) NOPASSWD: /usr/local/sbin/apply_firewall_rules.sh" > /etc/sudoers.d/firewall
chmod 440 /etc/sudoers.d/firewall

# Write initial pfSense config (writable by admin user for pfSsh.php)
WAN_IP="${WAN_IP:-10.99.2.168}"
LAN_IP="${LAN_IP:-10.99.1.2}"
cat > /conf/config.json <<CFGEOF
{
  "interfaces": {
    "wan": { "if": "re0", "ipaddr": "${WAN_IP}", "blockpriv": true },
    "lan": { "if": "re1", "ipaddr": "${LAN_IP}", "subnet": "24" }
  },
  "dhcpd": { "lan": { "range": { "from": "10.99.1.100", "to": "10.99.1.199" } } },
  "system": { "ssh": { "enable": "enabled" } },
  "nat": { "rule": [] },
  "filter": { "rule": [] }
}
CFGEOF
chown "$ADMIN_USER:$ADMIN_USER" /conf /conf/config.json

# Symlink sbin tools to bin so they're in PATH for non-interactive SSH
ln -sf /usr/local/sbin/pfSsh.php /usr/local/bin/pfSsh.php
ln -sf /usr/local/sbin/easyrule /usr/local/bin/easyrule

# Ensure easyrule log is writable by admin
touch /var/log/easyrule.log
chown "$ADMIN_USER:$ADMIN_USER" /var/log/easyrule.log

# Mock rc.reload_interfaces — in a real pfSense this reloads network config.
# In our mock, it updates the container's LAN IP if the config changed.
cat > /etc/rc.reload_interfaces <<'RCEOF'
#!/bin/bash
NEW_LAN=$(jq -r '.interfaces.lan.ipaddr' /conf/config.json 2>/dev/null)
if [ -n "$NEW_LAN" ] && [ "$NEW_LAN" != "null" ]; then
    # Find the LAN interface (eth0 typically in Docker)
    LAN_IFACE=$(ip -4 addr show | grep "10\.99\." | head -1 | awk '{print $NF}')
    if [ -n "$LAN_IFACE" ]; then
        CURRENT_IP=$(ip -4 addr show dev "$LAN_IFACE" | grep -oP '10\.99\.\d+\.\d+' | head -1)
        if [ "$CURRENT_IP" != "$NEW_LAN" ]; then
            # Add new IP and remove old one
            ip addr add "${NEW_LAN}/24" dev "$LAN_IFACE" 2>/dev/null || true
            ip addr del "${CURRENT_IP}/24" dev "$LAN_IFACE" 2>/dev/null || true
        fi
    fi
fi
RCEOF
chmod +x /etc/rc.reload_interfaces

# Mock ifconfig for WAN IP detection (bootstrap uses `ifconfig re0`)
cat > /usr/local/bin/ifconfig <<'IFEOF'
#!/bin/bash
# Mock ifconfig — returns WAN IP for the requested interface
IFACE="${1:-re0}"
WAN_IP=$(jq -r '.interfaces.wan.ipaddr' /conf/config.json 2>/dev/null)
echo "${IFACE}: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500"
echo "	inet ${WAN_IP} netmask 0xffffff00 broadcast ${WAN_IP%.*}.255"
IFEOF
chmod +x /usr/local/bin/ifconfig

# Mock /etc/rc.d/sshd (bootstrap calls sshd onerestart)
mkdir -p /etc/rc.d
cat > /etc/rc.d/sshd <<'SSHEOF'
#!/bin/bash
# Mock sshd rc script — no-op for restart
echo "sshd: $1"
SSHEOF
chmod +x /etc/rc.d/sshd

# Apply initial firewall rules (DROP WAN inbound, blockpriv enabled)
/usr/local/sbin/apply_firewall_rules.sh 2>/dev/null || echo "Warning: initial iptables rules failed"

# Start mock pfSense REST API in background
python3 /server.py &

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
