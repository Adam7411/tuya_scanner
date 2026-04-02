#!/bin/sh
set -e

CONFIG=/data/options.json

if [ -f "$CONFIG" ]; then
    SCAN_INTERVAL=$(python3 -c "import json;d=json.load(open('$CONFIG'));print(d.get('scan_interval',3600))")
    SCAN_DURATION=$(python3 -c "import json;d=json.load(open('$CONFIG'));print(d.get('scan_duration',18))")
else
    SCAN_INTERVAL=3600
    SCAN_DURATION=18
fi

export SCAN_INTERVAL
export SCAN_DURATION
export DATA_FILE="/data/devices.json"
export WIZARD_FILE="/data/wizard_devices.json"

echo "[TuyaScanner] Start — interwał: ${SCAN_INTERVAL}s, czas skanu: ${SCAN_DURATION}s"
echo "[TuyaScanner] DATA_FILE = ${DATA_FILE}"
echo "[TuyaScanner] WIZARD_FILE = ${WIZARD_FILE}"

exec python3 /scanner.py
