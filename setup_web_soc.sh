#!/bin/bash
echo "🛡️ Setting up Enterprise SOC Web Platform..."

cd ~/Desktop/"Soc Lab"
source venv/bin/activate

# Install web dependencies
pip install jinja2 aiofiles

# Create templates directory
mkdir -p templates

# Start web UI
echo "🌐 Starting Web Dashboard on port 8002..."
uvicorn src.web_ui:app --host 0.0.0.0 --port 8002 --reload &

echo ""
echo "✅ Enterprise SOC Web Platform is ready!"
echo ""
echo "Access your SOC Dashboard:"
echo "   🌐 http://localhost:8002"
echo ""
echo "Access your SOC API:"
echo "   📊 Stats: http://localhost:8001/api/stats"
echo "   📋 Alerts: http://localhost:8001/api/alerts"
echo "   🚨 Incidents: http://localhost:8001/api/incidents"
echo ""
echo "📱 Also accessible from any device on your network"
echo "   Use your IP address instead of localhost"
echo ""
echo "Example: http://$(hostname -I | awk '{print $1}'):8002"
