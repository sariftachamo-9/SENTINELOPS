#!/usr/bin/env python3
import requests
import json
from datetime import datetime
import time
import os
import sys

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

def draw_bar_chart(label, value, max_value=100, width=40):
    """Draw a simple bar chart"""
    bar_width = int((value / max_value) * width)
    bar = '█' * bar_width + '░' * (width - bar_width)
    return f"{label}: [{bar}] {value}"

def main():
    print("=" * 80)
    print("🛡️  ADVANCED SOC PLATFORM DASHBOARD")
    print("=" * 80)
    
    while True:
        clear()
        stats, alerts, incidents = get_data()
        
        # Header
        print("=" * 80)
        print(f"🛡️  SOC PLATFORM DASHBOARD")
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        # Statistics
        total_alerts = stats.get('total_alerts', 0)
        total_incidents = stats.get('total_incidents', 0)
        
        print(f"\n📊 STATISTICS:")
        print(f"   📨 Total Alerts: {total_alerts}")
        print(f"   🚨 Total Incidents: {total_incidents}")
        print(f"   ⏱️  Status: {stats.get('uptime', 'unknown')}")
        
        # Visual bars
        print(f"\n📈 TRENDS:")
        print(f"   Alerts:    {draw_bar_chart('', total_alerts % 50, 50, 30)}")
        print(f"   Incidents: {draw_bar_chart('', total_incidents % 50, 50, 30)}")
        
        # Recent alerts
        print(f"\n📋 RECENT ALERTS (Last 5):")
        if alerts:
            for alert in alerts[-5:]:
                severity = alert.get('severity', 'low')
                emoji = "🔴" if severity == 'critical' else "🟡" if severity == 'high' else "🟢"
                title = alert.get('title', 'Unknown')[:35]
                ts = alert.get('timestamp', '')[:19]
                print(f"   {emoji} [{ts}] {title}")
        else:
            print("   No alerts yet")
        
        # Severity distribution
        if alerts:
            severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for alert in alerts:
                sev = alert.get('severity', 'low')
                if sev in severity_count:
                    severity_count[sev] += 1
            
            print(f"\n📊 SEVERITY DISTRIBUTION:")
            for sev, count in severity_count.items():
                if count > 0:
                    emoji = "🔴" if sev == 'critical' else "🟡" if sev == 'high' else "🟢" if sev == 'medium' else "🔵"
                    print(f"   {emoji} {sev.title()}: {count}")
        
        # Footer
        print("\n" + "=" * 80)
        print(f"🔄 Auto-refreshes every 3 seconds | Alerts: {total_alerts} | Incidents: {total_incidents}")
        print("Press Ctrl+C to exit")
        print("=" * 80)
        
        time.sleep(3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")
        sys.exit(0)
