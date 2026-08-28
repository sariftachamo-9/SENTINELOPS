#!/bin/bash
set -e
echo "🛡️  Starting Enterprise SOC Platform..."

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✅ Virtual environment activated"
else
    echo "⛔ ERROR: venv not found. Run: python3 -m venv venv && pip install -r requirements.txt"
    exit 1
fi

UVICORN="$SCRIPT_DIR/venv/bin/python -m uvicorn"

mkdir -p logs

# Load .env (never commit .env to git)
if [ -f ".env" ]; then
    set -a; source .env; set +a
    echo "✅ Loaded .env configuration"
else
    echo "⚠️  No .env file found. Copy .env.example to .env and configure LAB_ADMIN_PASSWORD."
fi

# Require critical env vars
if [ -z "$LAB_ADMIN_PASSWORD" ]; then
    echo "⛔ ERROR: LAB_ADMIN_PASSWORD is not set in .env"
    exit 1
fi

if [ -z "$JWT_SECRET" ]; then
    echo "⛔ ERROR: JWT_SECRET is not set in .env"
    exit 1
fi

# Kill any existing SOC processes
pkill -f "uvicorn src.api:app" 2>/dev/null || true
pkill -f "uvicorn src.web_ui:app" 2>/dev/null || true
pkill -f "generate_realistic_alerts.py" 2>/dev/null || true
sleep 1

# 1. Start REST API (Port 8001)
$UVICORN src.api:app --host 0.0.0.0 --port 8001 > logs/api.log 2>&1 &
API_PID=$!
echo "✅ API Server starting on port 8001 (PID: $API_PID)"

# Wait until API is responsive (up to 15 seconds)
echo -n "   Waiting for API to be ready"
for i in $(seq 1 15); do
    if curl -s http://localhost:8001/api/v1/telemetry/health > /dev/null 2>&1; then
        echo " ✅"
        break
    fi
    echo -n "."
    sleep 1
done

# 2. Start Web UI Dashboard (Port 8002)
$UVICORN src.web_ui:app --host 0.0.0.0 --port 8002 > logs/web_ui.log 2>&1 &
WEB_PID=$!
echo "✅ Web UI Dashboard started on port 8002 (PID: $WEB_PID)"

# 3. Start Alert Generator (optional, only if script exists)
if [ -f "scripts/generate_realistic_alerts.py" ]; then
    python scripts/generate_realistic_alerts.py --continuous > logs/alerts.log 2>&1 &
    ALERT_PID=$!
    echo "✅ Threat Feed Generator started (PID: $ALERT_PID)"
fi

sleep 2

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP="127.0.0.1"
fi

echo ""
echo "=========================================================="
echo "🎯 ENTERPRISE SOC PLATFORM IS NOW RUNNING!"
echo "=========================================================="
echo "   🌐 Web Dashboard:  http://localhost:8002"
echo "   🌐 Network Access: http://${LOCAL_IP}:8002"
echo "   📊 API Health:     http://localhost:8001/api/v1/telemetry/health"
echo "   📖 API Docs:       http://localhost:8001/docs"
echo "   📁 Logs:           $SCRIPT_DIR/logs/"
echo ""
echo "   🔐 Default Login:  admin / $LAB_ADMIN_PASSWORD"
echo "   ⚠️  Change LAB_ADMIN_PASSWORD in .env before going public!"
echo "=========================================================="
echo "   To stop: ./production_stop.sh"
echo "=========================================================="

