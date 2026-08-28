#!/usr/bin/env python3
import requests
import json
from datetime import datetime
import time
import os

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def get_stats():
    try:
        r = requests.get("http://localhost:8001/api/stats", timeout=2)
        return r.json()
    except:
        return {}

def get_alerts():
    try:
        r = requests.get("http://localhost:8001/api/alerts", timeout=2)
        data = r.json()
        return data.get('alerts', [])
    except:
        return []

def display_dashboard():
    clear_screen()
    print("=" * 70)
    print("🛡️  SOC PLATFORM REAL-TIME DASHBOARD")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    stats = get_stats()
    alerts = get_alerts()
    
    print(f"\n📊 STATISTICS:")
    print(f"   📨 Total Alerts: {stats.get('total_alerts', 0)}")
    print(f"   🚨 Total Incidents: {stats.get('total_incidents', 0)}")
    print(f"   ⏱️  Status: {stats.get('uptime', 'unknown')}")
    
    print(f"\n📋 RECENT ALERTS (Last 5):")
    if alerts:
        recent = alerts[-5:]
        for alert in reversed(recent):
            severity = alert.get('severity', 'low')
            emoji = "🔴" if severity == 'critical' else "🟡" if severity == 'high' else "🟢"
            title = alert.get('title', 'Unknown')[:40]
            timestamp = alert.get('timestamp', '')[:19]
            print(f"   {emoji} [{timestamp}] {title}")
    else:
        print("   No alerts yet")
    
    print("\n" + "=" * 70)
    print("🔄 Auto-refreshes every 3 seconds | Press Ctrl+C to exit")

if __name__ == "__main__":
    try:
        while True:
            display_dashboard()
            time.sleep(3)
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")
        print(f"📊 Final stats: {get_stats()}")
