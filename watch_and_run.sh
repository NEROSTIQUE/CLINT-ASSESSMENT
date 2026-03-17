#!/bin/bash
# watch_and_run.sh - Monitors input.json and runs verify_ssrf.py on changes

INPUT_FILE="input.json"
SCRIPT="./verify_ssrf.py"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found."
    exit 1
fi

echo "Watching $INPUT_FILE for changes. Press Ctrl+C to stop."

# Monitor close_write (file saved) and move (if replaced)
while inotifywait -e close_write -e moved_to "$INPUT_FILE"; do
    echo "Detected change in $INPUT_FILE. Running verification..."
    python3 "$SCRIPT" "$INPUT_FILE"
    echo "----------------------------------------"
done
