#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8085
UPLOAD_DIR="$SCRIPT_DIR/uploads"

rm -rf "$UPLOAD_DIR"

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s -X POST -H "X-Filename: document.txt" -d "Hello world" "http://localhost:$PORT/")
if echo "$RESPONSE" | grep -q "File saved: document.txt"; then
    if [ -f "$UPLOAD_DIR/document.txt" ]; then
        if grep -q "Hello world" "$UPLOAD_DIR/document.txt"; then
            echo "NEGATIVE TEST PASSED: Benign text file saved correctly"
            kill $SERVER_PID 2>/dev/null
            exit 0
        fi
    fi
fi
echo "NEGATIVE TEST FAILED: Benign upload did not work as expected"
kill $SERVER_PID 2>/dev/null
exit 1