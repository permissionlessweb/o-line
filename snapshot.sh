#!/bin/bash

set -e

[ "$DEBUG" == "2" ] && set -x

# Configuration variables with defaults
SNAPSHOT_TIME="${SNAPSHOT_TIME:-00:00:00}"
SNAPSHOT_DAY="${SNAPSHOT_DAY:-*}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-$PROJECT_ROOT/data}"
SNAPSHOT_CMD="${SNAPSHOT_CMD:-$@}"
SNAPSHOT_PATH="${SNAPSHOT_PATH%/}" # custom: path to folder holding snapshots
SNAPSHOT_PREFIX="${SNAPSHOT_PREFIX:-$CHAIN_ID}"
SNAPSHOT_RETAIN="${SNAPSHOT_RETAIN:-2 days}"
SNAPSHOT_METADATA="${SNAPSHOT_METADATA:-1}"
SNAPSHOT_SAVE_FORMAT="${SNAPSHOT_SAVE_FORMAT:-$SNAPSHOT_FORMAT}"
CADDY_PORT="${CADDY_PORT:-3000}"
valid_snapshot_formats=(tar tar.gz tar.zst)
# Validate snapshot format
if ! echo "${valid_snapshot_formats[@]}" | grep -qiw -- "$SNAPSHOT_SAVE_FORMAT"; then
	SNAPSHOT_SAVE_FORMAT=tar.gz
fi
# Actual valid values not documented
# 27 is default value
# 31 is max value mentioned in project issues
# Since value > 27 requires special handling on decompression
# Only 27 is allowed at the moment when enabled
# See https://github.com/facebook/zstd/blob/v1.5.2/programs/zstd.1.md for more info
valid_zstd_long_values=(27)
# If non empty string and invalid value detected
# Set to default value assuming long should be enabled
if [ -n "$ZSTD_LONG" ] && ! echo "${valid_zstd_long_values[@]}" | grep -qiw -- "$ZSTD_LONG"; then
	ZSTD_LONG=27
fi
zstd_extra_args=""
if [ -n "$ZSTD_LONG" ]; then
	zstd_extra_arg="--long=$ZSTD_LONG"
fi

TIME=$(date -u +%T)
DOW=$(date +%u)

echo "$TIME: Starting server"
echo "$TIME: Snapshot will run at $SNAPSHOT_TIME on day $SNAPSHOT_DAY"
exec $SNAPSHOT_CMD &
PID=$!

## BEFORE SNAPSHOT, SETUP CADDY

# Create snapshot directory if it doesn't exist
mkdir -p "${SNAPSHOT_PATH}"

# Install Caddy if not already installed
if ! command -v caddy &>/dev/null; then
	log_this "Installing Caddy server"
	apt update
	apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
	curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
	apt update
	apt install -y caddy
fi

# Create Caddy configuration
log_this "Creating Caddy configuration"
cat >/etc/caddy/Caddyfile <<EOF
:$CADDY_PORT {
    root * ${SNAPSHOT_PATH}
    file_server {
        browse
    }
    rewrite /${SNAPSHOT_PREFIX}_latest.${SNAPSHOT_SAVE_FORMAT} {
        to /${SNAPSHOT_PREFIX}_latest.${SNAPSHOT_SAVE_FORMAT}
    }
}
EOF

# Start Caddy server
log_this "Starting Caddy server"
systemctl restart caddy.service || systemctl start caddy.service
log_this "Snapshot available at http://localhost:${CADDY_PORT}/${SNAPSHOT_PREFIX}_latest.${SNAPSHOT_SAVE_FORMAT}"

# Start the node process
log_this "Starting node process"
log_this "Snapshot will run at $SNAPSHOT_TIME on day $SNAPSHOT_DAY"
exec $SNAPSHOT_CMD &
PID=$!

# Main loop to check for snapshot time
while true; do
	TIME=$(date -u +%T)
	DOW=$(date +%u)
	if [[ ($SNAPSHOT_DAY == "*" || $SNAPSHOT_DAY == "$DOW") && $SNAPSHOT_TIME == "$TIME" ]]; then
		echo "$TIME: Stopping server"
		kill -15 $PID
		wait $PID

		echo "Stopping caddy..."
		systemctl stop caddy.service

		echo "$TIME: Running snapshot..."
		timestamp=$(date +"%Y-%m-%dT%H:%M:%S")
		snapshot_file="${SNAPSHOT_PATH}/${SNAPSHOT_PREFIX}_${timestamp}.${SNAPSHOT_SAVE_FORMAT}"
		latest_link="${SNAPSHOT_PATH}/${SNAPSHOT_PREFIX}_latest.${SNAPSHOT_SAVE_FORMAT}"
		log_this "Creating new snapshot: $snapshot_file"

		# Create the snapshot with appropriate compression
		$COMPRESS_CMD "$snapshot_file" -C "${SNAPSHOT_DIR}" .

		# Create symlink to latest snapshot
		log_this "Updating latest snapshot symlink"
		ln -sf "$snapshot_file" "$latest_link"

		# Always create metadata file
		metadata_file="${SNAPSHOT_PATH}/${SNAPSHOT_PREFIX}_metadata.json"
		snapshot_size=$(du -sb "$snapshot_file" | cut -f1)

		cat >"$metadata_file" <<EOF
{
  "chain_id": "${CHAIN_ID}",
  "prefix": "${SNAPSHOT_PREFIX}",
  "latest_snapshot": "${SNAPSHOT_PREFIX}_${timestamp}.${SNAPSHOT_SAVE_FORMAT}",
  "timestamp": "${timestamp}",
  "size_bytes": ${snapshot_size},
  "format": "${SNAPSHOT_SAVE_FORMAT}"
}
EOF
		log_this "Created metadata file: $metadata_file"

		# Clean up old snapshots
		cleanup_old_snapshots

		# Restart Caddy to serve the new snapshot
		echo "Restarting caddy"
		systemctl start caddy.service
		echo "New snapshot available at http://localhost:${CADDY_PORT}/${SNAPSHOT_PREFIX}_latest.${SNAPSHOT_SAVE_FORMAT}"

		# Restart the node process
		echo "Restarting server"
		exec $SNAPSHOT_CMD &
		PID=$!
	else
		# Check if the process is still running
		if ! kill -0 $PID 2>/dev/null; then
			echo "Process has died. Exiting"
			exit 1
		fi
	fi

	# Sleep to avoid high CPU usage
	sleep 1s
done

# Function to clean up old snapshots
cleanup_old_snapshots() {
	log_this "Cleaning up snapshots older than $SNAPSHOT_RETAIN"
	find "${SNAPSHOT_PATH}" -name "${SNAPSHOT_PREFIX}_*.${SNAPSHOT_SAVE_FORMAT}" -type f -mtime +"${SNAPSHOT_RETAIN%%[[:space:]]*}" -delete
}
