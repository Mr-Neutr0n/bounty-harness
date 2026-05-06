#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8083

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/fetch?url=http://127.0.0.1:$PORT/")
if echo "$RESPONSE" | grep -q "Send a ?url="; then
    echo "POSITIVE TEST PASSED: SSRF successfully fetched the local server"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "POSITIVE TEST FAILED: SSRF did not fetch local server"
    echo "Response: $RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi