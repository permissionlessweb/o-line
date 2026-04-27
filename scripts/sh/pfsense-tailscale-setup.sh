#!/bin/sh
# pfsense-tailscale-setup.sh
#
# Install Tailscale on pfSense and register with Headscale control plane.
# Run via SSH from o-line: ssh -i <key> admin@<pfsense> < this-script.sh
#
# Required environment variables (passed via ssh -o SendEnv or inline):
#   HEADSCALE_URL    - Headscale control plane URL (e.g. https://admin.terp.network)
#   HEADSCALE_KEY    - Preauth key for registration
#   PFSENSE_HOSTNAME - Hostname to register as (default: pfsense)
#   ADVERTISE_ROUTES - Comma-separated subnets to advertise (default: 192.168.1.0/24)
#
# Usage from o-line:
#   oline vpn pfsense-setup --host 192.168.1.1 --ssh-key ~/.ssh/pfsense_key
#
# Manual usage:
#   HEADSCALE_URL=https://admin.terp.network \
#   HEADSCALE_KEY=<preauth-key> \
#   ssh -i ~/.ssh/pfsense_key admin@192.168.1.1 'sh -s' < pfsense-tailscale-setup.sh

set -e
HOSTNAME="${PFSENSE_HOSTNAME:-pfsense}"
ROUTES="${ADVERTISE_ROUTES:-192.168.1.0/24}"
TAILSCALE_VER="1.82.5"

if [ -z "$HEADSCALE_URL" ] || [ -z "$HEADSCALE_KEY" ]; then
    echo "ERROR: HEADSCALE_URL and HEADSCALE_KEY must be set"
    exit 1
fi

echo "=== pfSense Tailscale Setup ==="
echo "  Headscale:  $HEADSCALE_URL"
echo "  Hostname:   $HOSTNAME"
echo "  Routes:     $ROUTES"

# Detect pfSense version and architecture
ARCH=$(uname -m)
FREEBSD_VER=$(freebsd-version -u 2>/dev/null | cut -d- -f1 || uname -r | cut -d- -f1)
echo "  FreeBSD:    $FREEBSD_VER ($ARCH)"

# Check if Tailscale is already installed
if command -v tailscale >/dev/null 2>&1; then
    echo "  Tailscale already installed: $(tailscale version 2>/dev/null | head -1)"
else
    echo "  Installing Tailscale..."

    # pfSense uses pkg for package management
    # Tailscale is available as a FreeBSD package
    if command -v pkg >/dev/null 2>&1; then
        pkg install -y tailscale || {
            # If pkg repo doesn't have it, try fetching the binary directly
            echo "  pkg install failed, trying direct download..."
           
            case "$ARCH" in
                amd64|x86_64) TS_ARCH="amd64" ;;
                arm64|aarch64) TS_ARCH="arm64" ;;
                *) echo "ERROR: unsupported arch $ARCH"; exit 1 ;;
            esac
            fetch -o /tmp/tailscale.txz \
                "https://pkg.freebsd.org/FreeBSD:${FREEBSD_VER%%.*}:${TS_ARCH}/latest/All/tailscale-${TAILSCALE_VER}.pkg" || {
                echo "ERROR: could not download Tailscale package"
                exit 1
            }
            pkg add /tmp/tailscale.txz
            rm -f /tmp/tailscale.txz
        }
    else
        echo "ERROR: pkg not found. Is this pfSense?"
        exit 1
    fi
fi

# Enable and start tailscaled
echo "  Enabling tailscaled service..."
sysrc tailscaled_enable="YES" 2>/dev/null || \
    echo 'tailscaled_enable="YES"' >> /etc/rc.conf

# Start tailscaled if not running
if ! pgrep -x tailscaled >/dev/null 2>&1; then
    echo "  Starting tailscaled..."
    service tailscaled start 2>/dev/null || /usr/local/sbin/tailscaled --state=/var/db/tailscale/tailscaled.state &
    sleep 3
fi

# Register with Headscale
echo "  Registering with Headscale..."
tailscale up \
    --login-server="$HEADSCALE_URL" \
    --authkey="$HEADSCALE_KEY" \
    --hostname="$HOSTNAME" \
    --advertise-routes="$ROUTES" \
    --accept-routes

# Verify registration
sleep 2
echo ""
echo "=== Registration Complete ==="
tailscale status
echo ""
echo "  Next steps:"
echo "  1. Approve routes in Headscale:"
echo "     oline vpn nodes list"
echo "     oline vpn nodes routes <node-id> $ROUTES"
echo "  2. Enable IP forwarding in pfSense (System > Advanced > Networking)"
echo "  3. Add firewall rule: allow Tailscale interface to LAN"
