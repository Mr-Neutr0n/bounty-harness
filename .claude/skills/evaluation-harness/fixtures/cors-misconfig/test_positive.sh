#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8084

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

HEADERS=$(curl -s -D - -o /dev/null -H "Origin: http://evil.com" "http://localhost:$PORT/")
if echo "$HEADERS" | grep -qi "Access-Control-Allow-Origin: http://evil.com"; then
    if echo "$HEADERS" | grep -qi "Access-Control-Allow-Credentials: true"; then
        echo "POSITIVE TEST PASSED: CORS reflects arbitrary Origin with credentials"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "POSITIVE TEST FAILED: CORS misconfiguration not detected"
echo "Headers: $HEADERS"
kill $SERVER_PID 2>/dev/null
exit 1