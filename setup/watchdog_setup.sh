#!/bin/bash

PROCESS_NAME="your_process_name"
PYTHON_SCRIPT_PATH="/path/to/your/python/script.py"

# Check if the process is running
if pgrep "$PROCESS_NAME" > /dev/null; then
    # Check if the python script is already running to avoid multiple instances
    if ! pgrep -f "$PYTHON_SCRIPT_PATH" > /dev/null; then
        nohup python3 "$PYTHON_SCRIPT_PATH" &> /dev/null &
    fi
fi


# chmod +x watchdog.sh
# crontab -e
# * * * * * /path/to/watchdog.sh   <- every minute
