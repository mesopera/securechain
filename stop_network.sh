#!/usr/bin/env bash
# stop_network.sh
for ID in 1 2 3 4 5; do
    PID_FILE="pids/node${ID}.pid"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        kill "$PID" 2>/dev/null && echo "Stopped Node $ID (pid $PID)" || echo "Node $ID already stopped"
        rm "$PID_FILE"
    fi
done