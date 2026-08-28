import requests
import json
from datetime import datetime
import time
import os

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def get_data():
    try:
        stats = requests.get("http://localhost:8001/api/stats", timeout=2).json()
        alerts = requests.get("http://localhost:8001/api/alerts", timeout=2).json()
        incidents = requests.get("http://localhost:8001/api/incidents", timeout=2).json()
        return stats, alerts.get('alerts', []), incidents.get('incidents', [])
    except:
        return {}, [], []

def main():
    while True:
        clear()
        stats, alerts, incidents = get_data()
        
        print("=" * 70)
        print(f"🛡️  SOC PLATFORM DASHBOARD")
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        print(f"\n📊 STATISTICS:")
        print(f"   📨 Alerts: {stats.get('total_alerts', 0)}")
        print(f"   🚨 Incidents: {stats.get('total_incidents', 0)}")
        print(f"   📈 Events: {stats.get('events_processed', 0)}")
        print(f"   ⏱️  Status: {stats.get('uptime', 'unknown')}")
        
        print(f"\n📋 ALERTS (Last 5):")
        if alerts:
            for alert in alerts[-5:]:
                severity = alert.get('severity', 'low')
                emoji = "🔴" if severity == 'critical' else "🟡" if severity == 'high' else "🟢"
                title = alert.get('title', 'Unknown')[:40]
                ts = alert.get('timestamp', '')[:19]
                print(f"   {emoji} [{ts}] {title}")
        else:
            print("   No alerts yet")
        
        print(f"\n🚨 INCIDENTS (Last 5):")
        if incidents:
            for inc in incidents[-5:]:
                status = inc.get('status', 'unknown')
                emoji = "🔴" if status == 'open' else "🟢"
                title = inc.get('title', 'Unknown')[:40]
                ts = inc.get('created_at', '')[:19]
                print(f"   {emoji} [{ts}] {title} ({status})")
        else:
            print("   No incidents yet")
        
        print("\n" + "=" * 70)
        print("🔄 Refreshes every 3 seconds | Press Ctrl+C to exit")
        
        time.sleep(3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")
