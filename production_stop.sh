#!/bin/bash
echo "🛑 Stopping SENTINELOPS services..."

pkill -f "python src/main.py" 2>/dev/null
pkill -f "uvicorn src.api:app" 2>/dev/null
pkill -f "uvicorn src.web_ui:app" 2>/dev/null
pkill -f "generate_realistic_alerts.py" 2>/dev/null
pkill -f "continuous_alerts.py" 2>/dev/null

echo "✅ All SENTINELOPS processes stopped."
