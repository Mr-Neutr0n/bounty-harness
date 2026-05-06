#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8081

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/search?q=<script>alert(1)</script>")
if echo "$RESPONSE" | grep -q "<script>alert(1)</script>"; then
    echo "POSITIVE TEST PASSED: Script tag reflected in response"
    kill $SERVER_PID 2>/dev/null
    exit 0
else
    echo "POSITIVE TEST FAILED: Script tag not reflected"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi