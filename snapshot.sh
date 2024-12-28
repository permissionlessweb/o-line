#!/bin/bash

set -e

[ "$DEBUG" == "2" ] && set -x

SNAPSHOT_TIME="${SNAPSHOT_TIME:-00:00:00}"
SNAPSHOT_DAY="${SNAPSHOT_DAY:-*}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-$PROJECT_ROOT/data}"
SNAPSHOT_CMD="${SNAPSHOT_CMD:-$@}"
SNAPSHOT_PATH="${SNAPSHOT_PATH%/}"
SNAPSHOT_PREFIX="${SNAPSHOT_PREFIX:-$CHAIN_ID}"
SNAPSHOT_RETAIN="${SNAPSHOT_RETAIN:-2 days}"
SNAPSHOT_METADATA="${SNAPSHOT_METADATA:-1}"
SNAPSHOT_SAVE_FORMAT="${SNAPSHOT_SAVE_FORMAT:-$SNAPSHOT_FORMAT}"

valid_snapshot_formats=(tar tar.gz tar.zst)
# If not one of valid format values, set it to default value
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

# create new caddy file 
echo "Creating new Caddy file"
cat > /etc/caddy/Caddyfile <<EOF
:80 {
    root * ${SNAPSHOT_PATH}
    file_server {
        browse
    }
     rewrite /terp_latest.tar.gz {
        to /${SNAPSHOT_PREFIX}_latest.tar.gz
    }
}
EOF

echo "$TIME: Starting server"
echo "$TIME: Snapshot will run at $SNAPSHOT_TIME on day $SNAPSHOT_DAY"
exec $SNAPSHOT_CMD &
PID=$!

while true; do
    TIME=$(date -u +%T)
    DOW=$(date +%u)
    if [[ ($SNAPSHOT_DAY == "*") || ($SNAPSHOT_DAY == $DOW) ]] && [[ $SNAPSHOT_TIME == $TIME ]]; then
        get block height 
        echo "$TIME: Stopping terp node"
        kill -15 $PID
        wait

        echo "$TIME: Stopping caddy"
        systemctl stop caddy.service

        echo "$TIME: Creating snapshot"
        timestamp=$(date +"%Y-%m-%dT%H:%M:%S")
        SNAPSHOT_SIZE=$(du -sb $SNAPSHOT_DIR | cut -f1)

        mkdir -p "${SNAPSHOT_PATH}"
        tar -czf "${SNAPSHOT_PATH}/${SNAPSHOT_PREFIX}_${timestamp}.tar.gz" -C "${SNAPSHOT_DIR}" .
        ln -sf "${SNAPSHOT_PATH}/${SNAPSHOT_PREFIX}_${timestamp}.tar.gz" "${SNAPSHOT_PATH}/terp_latest.tar.gz"

        # Serve snapshot via caddy
        log_this "Serving new snapshot"
        systemctl start caddy.service &
        caddy_pid=$!
        echo "$TIME: Snapshot available at http://localhost:80/terp_latest.tar.gz"
    fi
        echo "$TIME: Restarting terpd"
        exec $SNAPSHOT_CMD &
        PID=$!
        sleep 1s
    else
        if ! kill -0 $PID; then
            echo "$TIME: Process has died. Exiting"
            break;
        fi
    fi
done

# todo: after n snapshots created prune k # of snapshots by saving to jackal storage provider