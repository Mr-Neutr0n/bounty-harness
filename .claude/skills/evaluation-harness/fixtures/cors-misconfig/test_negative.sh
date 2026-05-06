#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8084

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

HEADERS=$(curl -s -D - -o /dev/null "http://localhost:$PORT/")
if echo "$HEADERS" | grep -qi "Access-Control-Allow-Origin"; then
    echo "NEGATIVE TEST FAILED: CORS header present without an Origin request"
    kill $SERVER_PID 2>/dev/null
    exit 1
else
    echo "NEGATIVE TEST PASSED: No CORS headers without Origin (benign behavior)"
    kill $SERVER_PID 2>/dev/null
    exit 0
fi