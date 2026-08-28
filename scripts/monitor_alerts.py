#!/usr/bin/env python3
import requests
import json
import time
import subprocess
import os
from datetime import datetime

def check_platform():
    try:
        # Check API health
        r = requests.get("http://localhost:8001/health", timeout=2)
        if r.status_code != 200:
            return False, "API health check failed"
        
        # Check stats
        r = requests.get("http://localhost:8001/api/stats", timeout=2)
        stats = r.json()
        alerts = stats.get('total_alerts', 0)
        incidents = stats.get('total_incidents', 0)
        
        return True, f"Alerts: {alerts}, Incidents: {incidents}"
    except Exception as e:
        return False, f"Platform unreachable: {str(e)}"

def restart_platform():
    """Restart the platform"""
    try:
        # Kill existing processes
        os.system("pkill -f 'python src/main.py' 2>/dev/null")
        os.system("pkill -f 'uvicorn src.api' 2>/dev/null")
        time.sleep(2)
        
        # Start platform
        os.chdir("/home/jenishkali/Desktop/Soc Lab")
        os.system("source venv/bin/activate && python src/main.py &")
        time.sleep(2)
        os.system("source venv/bin/activate && uvicorn src.api:app --host 0.0.0.0 --port 8001 --reload &")
        
        return True
    except Exception as e:
        print(f"Failed to restart: {e}")
        return False

if __name__ == "__main__":
    print("��️  SOC Platform Monitor Started")
    print("Press Ctrl+C to stop")
    
    while True:
        try:
            status, message = check_platform()
            if not status:
                print(f"[{datetime.now()}] ⚠️ Issue: {message}")
                print("🔄 Attempting to restart...")
                if restart_platform():
                    print("✅ Platform restarted successfully")
                else:
                    print("❌ Failed to restart platform")
            else:
                print(f"[{datetime.now()}] ✅ Platform OK - {message}")
            
            time.sleep(30)  # Check every 30 seconds
            
        except KeyboardInterrupt:
            print("\n👋 Monitor stopped")
            break
        except Exception as e:
            print(f"[{datetime.now()}] ❌ Monitor error: {e}")
            time.sleep(30)
