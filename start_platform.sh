#!/bin/bash
echo "🛡️ Starting SENTINELOPS..."

# Go to project directory
cd ~/Desktop/"SENTINELOPS"

# Activate virtual environment
source venv/bin/activate

# Kill any existing processes
pkill -f "python src/main.py" 2>/dev/null
pkill -f "uvicorn src.api" 2>/dev/null
sleep 2

# Start the platform
echo "🚀 Starting main platform..."
python src/main.py &
MAIN_PID=$!

# Start the API
echo "🚀 Starting API server..."
uvicorn src.api:app --host 0.0.0.0 --port 8001 --reload &
API_PID=$!

sleep 3

echo ""
echo "✅ SENTINELOPS is running!"
echo "   📊 Main Platform PID: $MAIN_PID"
echo "   🔗 API PID: $API_PID"
echo "   🌐 API: http://localhost:8001"
echo "   🏥 Health: http://localhost:8001/health"
echo ""
echo "📋 To run dashboard:"
echo "   source venv/bin/activate"
echo "   python dashboards/dashboard.py"
echo ""
echo "🛑 To stop:"
echo "   pkill -f 'python src/main.py'"
echo "   pkill -f 'uvicorn src.api'"
