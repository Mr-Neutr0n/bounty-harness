#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8086

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:$PORT/")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
if [ "$HTTP_CODE" = "401" ]; then
    echo "NEGATIVE TEST PASSED: No token returns 401 (benign behavior)"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "NEGATIVE TEST FAILED: Expected 401 without token, got $HTTP_CODE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi