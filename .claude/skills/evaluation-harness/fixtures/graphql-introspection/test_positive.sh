#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8087

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}' "http://localhost:$PORT/graphql")
if echo "$RESPONSE" | grep -q '"__schema"'; then
    if echo "$RESPONSE" | grep -q '"passwordHash"'; then
        echo "POSITIVE TEST PASSED: GraphQL introspection returns schema with sensitive fields"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "POSITIVE TEST FAILED: Introspection did not return schema"
echo "Response: $RESPONSE"
kill $SERVER_PID 2>/dev/null
exit 1