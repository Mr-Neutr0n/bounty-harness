#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8083

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/fetch?url=http://non-existent-domain-xyz.test")
if echo "$RESPONSE" | grep -q "Fetch Error"; then
    echo "NEGATIVE TEST PASSED: Invalid URL returned error (no internal data leaked)"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "NEGATIVE TEST FAILED: Unexpected response for invalid URL"
    echo "Response: $RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi