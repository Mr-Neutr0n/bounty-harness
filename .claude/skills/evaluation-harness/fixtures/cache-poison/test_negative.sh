#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8088

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s "http://localhost:$PORT/")
if echo "$RESPONSE" | grep -q "/static/tracking.js"; then
    if echo "$RESPONSE" | grep -qv "evil.com"; then
        echo "NEGATIVE TEST PASSED: Normal response uses relative URLs (benign behavior)"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "NEGATIVE TEST FAILED: Normal response did not use safe relative URLs"
echo "Response: $RESPONSE"
kill $SERVER_PID 2>/dev/null
exit 1