#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8082

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/search?username=admin'%20OR%20'1'='1")
if echo "$RESPONSE" | grep -q "(2, 'user'"; then
    echo "POSITIVE TEST PASSED: SQL injection returned extra row"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "POSITIVE TEST FAILED: SQL injection did not return expected result"
    echo "Response: $RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi