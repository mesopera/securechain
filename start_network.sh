#!/usr/bin/env bash
# start_network.sh — spin up 5 validator nodes as background processes
# Usage: bash start_network.sh
# Stop:  bash stop_network.sh

set -e
mkdir -p data logs pids

ALL_PORTS="5001,5002,5003,5004,5005"

for ID in 1 2 3 4 5; do
    PORT=$((5000 + ID))
    PEERS=$(echo $ALL_PORTS | tr ',' '\n' | grep -v "^${PORT}$" | tr '\n' ',' | sed 's/,$//')

    echo "Starting Node $ID on port $PORT  peers=$PEERS"
    python network/node.py --id $ID --port $PORT --peers $PEERS \
        > logs/node${ID}.log 2>&1 &
    echo $! > pids/node${ID}.pid
    sleep 0.3
done

echo ""
echo "✅ All 5 nodes running."
echo "   Logs  : logs/node{1..5}.log"
echo "   Status: curl http://localhost:5001/status"
echo "   Stop  : bash stop_network.sh"