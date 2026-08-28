#!/bin/bash
echo "👁️  Monitoring SOC Platform..."

cd ~/Desktop/"Soc Lab"
source venv/bin/activate

while true; do
    # Check if platform is running
    if ! pgrep -f "python src/main.py" > /dev/null; then
        echo "❌ Platform stopped! Restarting..."
        python src/main.py &
    fi
    
    if ! pgrep -f "uvicorn src.api" > /dev/null; then
        echo "❌ API stopped! Restarting..."
        uvicorn src.api:app --host 0.0.0.0 --port 8001 --reload &
    fi
    
    sleep 10
done
