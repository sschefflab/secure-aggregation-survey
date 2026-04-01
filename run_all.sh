#!/usr/bin/env bash
# Run Flask server and three clients, collecting logs.
set -euo pipefail


# Set ROOT_DIR to absolute path of directory containing this script
# Set SRC_DIR to ROOT_DIR/src
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"
SRC_DIR="$ROOT_DIR/src"
LOG_DIR="$ROOT_DIR/log"


mkdir -p "$LOG_DIR"


PYTHON_BIN="$SRC_DIR/.venv/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
 PYTHON_BIN="python"
fi


# Start server
echo "Starting server, logging to $LOG_DIR/server.log..."
"$PYTHON_BIN" "$SRC_DIR/server.py" > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!


# Wait
sleep 1


# Generate signing/verification keys
echo "Generating signing/verification keys..."
"$PYTHON_BIN" "$SRC_DIR/ttp.py" --N 10


# Start clients
CLIENT_PIDS=""
for i in 1 2 3 4 5 6 7 8 9 10; do
 echo "Starting client $i, logging to $LOG_DIR/client${i}.log..."
 "$PYTHON_BIN" "$SRC_DIR/client.py" --id "$i" --vec "1,2,4" --signingkey "keys/sign-${i}.key" --verificationkeys "keys/verification_keys.json" > "$LOG_DIR/client${i}.log" 2>&1 &
 CLIENT_PIDS="$CLIENT_PIDS $!"
 sleep 0.1
done


# Wait for clients to finish
for client_pid in $CLIENT_PIDS; do
 wait "$client_pid" || true
 echo "Client $client_pid finished."
 sleep 0.1
done


# Stop server
kill "$SERVER_PID" || true
echo "Server $SERVER_PID stopped."


# Done
echo "Done."




