#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8082

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/search?username=admin")
if echo "$RESPONSE" | grep -q "Error:"; then
    echo "NEGATIVE TEST FAILED: Benign query returned an error"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi
if echo "$RESPONSE" | grep -q "(1, 'admin'"; then
    echo "NEGATIVE TEST PASSED: Benign query returned only expected row"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "NEGATIVE TEST FAILED: Unexpected response for benign input"
    echo "Response: $RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi