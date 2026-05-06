#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8081

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/search?q=hello")
if echo "$RESPONSE" | grep -q "hello"; then
    echo "NEGATIVE TEST PASSED: Normal text reflected without XSS"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "NEGATIVE TEST FAILED: Normal text not reflected"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi