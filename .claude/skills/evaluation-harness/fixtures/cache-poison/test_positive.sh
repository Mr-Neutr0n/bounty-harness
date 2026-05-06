#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8088

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s -H "X-Forwarded-Host: evil.com" "http://localhost:$PORT/")
if echo "$RESPONSE" | grep -q "evil.com/tracking.js"; then
    if echo "$RESPONSE" | grep -q "Cache-Control: public, max-age=3600" || echo "$RESPONSE" | grep -q "evil.com/styles.css"; then
        echo "POSITIVE TEST PASSED: X-Forwarded-Host reflected in cacheable response"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "POSITIVE TEST FAILED: Cache poisoning vector not present"
echo "Response: $RESPONSE"
kill $SERVER_PID 2>/dev/null
exit 1