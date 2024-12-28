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

echo "$TIME: Starting server"
echo "$TIME: Snapshot will run at $SNAPSHOT_TIME on day $SNAPSHOT_DAY"
exec $SNAPSHOT_CMD &
PID=$!

while true; do
    TIME=$(date -u +%T)
    DOW=$(date +%u)
    if [[ ($SNAPSHOT_DAY == "*") || ($SNAPSHOT_DAY == $DOW) ]] && [[ $SNAPSHOT_TIME == $TIME ]]; then
        echo "$TIME: Stopping server"
        kill -15 $PID
        wait

        echo "$TIME: Running snapshot"
        timestamp=$(date +"%Y-%m-%dT%H:%M:%S")

        SNAPSHOT_SIZE=$(du -sb $SNAPSHOT_DIR | cut -f1)



        # compress snapshot_path to tarball 
        log_this "Creating new snapshot"
        time tar cf ${HOME}/${SNAP_NAME} -C ${SNAPSHOT_DIR} . &>>${LOG_PATH}

        # move compress image to snapshot folder 
        log_this "Moving new snapshot to ${SNAP_PATH}"
        mv ${HOME}/${CHAIN_ID}*tar ${SNAP_PATH} &>>${LOG_PATH}


    fi
        if [[ $SNAPSHOT_RETAIN != "0" || $SNAPSHOT_METADATA != "0" ]]; then
            fi
            snapshots=()
            for line in "${s3Files[@]}"; do
                createDate=`echo $line|awk {'print $1" "$2'}`
                createDate=`date -d"$createDate" +%s`
                fileName=`echo $line|awk '{$1=$2=$3=""; print $0}' | sed 's/^[ \t]*//'`
                if [[ -n $SNAPSHOT_METADATA_URL && $SNAPSHOT_METADATA_URL != */ ]]; then
                    fileUrl="${SNAPSHOT_METADATA_URL}/${fileName}"
                else
                    fileUrl="${SNAPSHOT_METADATA_URL}${fileName}"
                fi
                ## prune any snapshots if configured
                if [ "$SNAPSHOT_RETAIN" != "0" ]; then
                    olderThan=`date -d"-$SNAPSHOT_RETAIN" +%s`
                    if [[ $createDate -lt $olderThan ]]; then
                        if [[ $fileName != "" ]]; then
                            echo "$TIME: Deleting snapshot $fileName"
                        fi
                    else
                        snapshots+=("$fileUrl")
                    fi
                else
                    snapshots+=("$fileUrl")
                fi
            done;

            if [ "$SNAPSHOT_METADATA" != "0" ]; then
                echo "$TIME: Uploading metadata"
                snapshotJson="[]"
                for url in ${snapshots[@]}; do
                    snapshotJson="$(echo $snapshotJson | jq ".+[\"$url\"]")"
                done
                else
                fi
            fi
        fi

        echo "$TIME: Restarting server"
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
