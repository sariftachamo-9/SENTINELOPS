#!/bin/bash
echo "🛡️ Starting SOC Platform..."
cd ~/Desktop/"Soc Lab"
source venv/bin/activate

# Kill any existing processes
pkill -f "python src/main.py" 2>/dev/null
pkill -f "uvicorn src.api" 2>/dev/null

# Start platform
python src/main.py &
echo "✅ Platform started (PID: $!)"

# Start API
uvicorn src.api:app --host 0.0.0.0 --port 8001 --reload &
echo "✅ API started (PID: $!)"

sleep 2
echo ""
echo "📊 SOC Platform is running!"
echo "   API: http://localhost:8001"
echo "   Health: http://localhost:8001/health"
echo "   Dashboard: python dashboards/simple_dashboard.py"
echo ""
echo "To stop: pkill -f 'python src/main.py' && pkill -f 'uvicorn src.api'"
