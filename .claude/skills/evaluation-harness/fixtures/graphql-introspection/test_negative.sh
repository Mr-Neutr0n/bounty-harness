#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8087

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{ user(id: 1) { id email } }"}' "http://localhost:$PORT/graphql")
if echo "$RESPONSE" | grep -q '"data"'; then
    if echo "$RESPONSE" | grep -q '"passwordHash"' || echo "$RESPONSE" | grep -q '"__schema"'; then
        echo "NEGATIVE TEST FAILED: Normal query leaked schema or sensitive fields"
        kill $SERVER_PID 2>/dev/null
        exit 1
    else
        echo "NEGATIVE TEST PASSED: Normal query returns only requested data"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "NEGATIVE TEST FAILED: Normal query did not return expected data"
echo "Response: $RESPONSE"
kill $SERVER_PID 2>/dev/null
exit 1