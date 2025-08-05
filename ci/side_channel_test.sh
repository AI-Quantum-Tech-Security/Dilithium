#!/bin/bash

set -e
#load .env file
ENV_FILE=".env"
if [ -f "$ENV_FILE" ]; then
    echo "Loading environment variables from $ENV_FILE"
    source "$ENV_FILE"
else
    echo "Warning: $ENV_FILE not found. Proceeding without it."
fi

HOST="localhost"
PORT="3000"
API_URL="http://${HOST}:${PORT}/sign"
AUTH_TOKEN="${API_TOKEN:-}"
REQUESTS_COUNT=1000
MESSAGE_LENGTHS=(10 100 1000 10000 50000)


start_server() {
  echo "Starting the server..."
  cargo run --bin your_service_name &
  SERVER_PID=$!
  sleep 5
  echo "Server started with PID: ${SERVER_PID}"
}

stop_server() {
  echo "Stopping the server..."
  kill ${SERVER_PID}
  wait ${SERVER_PID} 2>/dev/null
  echo "Server stopped."
}

#timing test for a given message length
run_test() {
  local length=$1
  local message_data=$(head -c ${length} /dev/urandom | base64)

  echo "  Running test for message length: ${length} bytes"

  for i in $(seq 1 ${REQUESTS_COUNT}); do
    start_time=$(gdate +%s%N || date +%s%N)

    curl -s -X POST "${API_URL}" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer ${AUTH_TOKEN}" \
      -d '{"message": "'"${message_data}"'"}' > /dev/null

    end_time=$(gdate +%s%N || date +%s%N)
    elapsed_time=$((end_time - start_time))

    echo "${length},${elapsed_time}" >> timings.csv
  done
}

echo "--- Dilithium Side-Channel Timing Test ---"

# Crucial check: Exit if the API_TOKEN is not set
if [ -z "$API_TOKEN" ]; then
    echo "Error: API_TOKEN is not set. Please add it to your .env file."
    exit 1
fi

if [ -f timings.csv ]; then
  rm timings.csv
fi

start_server

if ! curl -s "${API_URL}" > /dev/null; then
  echo "Error: Server failed to start. Aborting."
  stop_server
  exit 1
fi


#tests for all configured message lengths
for len in "${MESSAGE_LENGTHS[@]}"; do
  run_test "${len}"
done

stop_server

echo "--- Analysis ---"
echo "Timing data collected in timings.csv"

echo "Performing correlation analysis with Python..."
python3 -c '
import pandas as pd
df = pd.read_csv("timings.csv", header=None, names=["length", "time"])
correlation = df["length"].corr(df["time"])
print(f"Correlation between message length and signing time: {correlation:.4f}")
if abs(correlation) > 0.5:
    print("WARNING: High correlation detected! This may indicate a timing side-channel vulnerability.")
else:
    print("SUCCESS: Low correlation detected. The signing time appears to be independent of message length.")
'

echo "--- Test Complete ---"