#!/bin/bash
echo "🔄 Fixing SENTINELOPS..."

cd ~/Desktop/"SENTINELOPS"
source venv/bin/activate

# Stop everything
echo "🛑 Stopping services..."
./production_stop.sh 2>/dev/null
pkill -f "uvicorn" 2>/dev/null
sleep 2

# Start production
echo "🚀 Starting production..."
./production_start.sh
sleep 5

# Generate alerts
echo "📨 Generating alerts..."
python scripts/generate_realistic_alerts.py

# Send more alerts
echo "📨 Sending additional alerts..."
for i in {1..30}; do
  curl -s -X POST http://localhost:8001/api/alerts \
    -H "Content-Type: application/json" \
    -d "{\"title\":\"Alert $i\",\"severity\":\"high\",\"description\":\"Security alert $i\"}" > /dev/null
  echo -n "."
done
echo " ✅ Done!"

# Start Web UI
echo "🌐 Starting Web UI..."
uvicorn src.web_ui:app --host 0.0.0.0 --port 8002 --reload &
sleep 3

# Show stats
echo ""
echo "📊 Current Status:"
curl -s http://localhost:8001/api/stats | python -m json.tool

echo ""
echo "✅ Fix Complete!"
echo "🌐 Access your SOC Dashboard: http://localhost:8002"
echo "📱 Or from other devices: http://192.168.1.88:8002"
