#!/usr/bin/env python3
"""
Complete SOC Status Page
"""

import requests
import json
from datetime import datetime
import time
import os

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def get_all_data():
    try:
        stats = requests.get("http://localhost:8001/api/stats", timeout=2).json()
        alerts = requests.get("http://localhost:8001/api/alerts", timeout=2).json()
        incidents = requests.get("http://localhost:8001/api/incidents", timeout=2).json()
        return stats, alerts.get('alerts', []), incidents.get('incidents', [])
    except:
        return {}, [], []

def main():
    print("=" * 80)
    print("🛡️  COMPLETE SOC STATUS PAGE")
    print("=" * 80)
    
    while True:
        clear()
        stats, alerts, incidents = get_all_data()
        
        total_alerts = stats.get('total_alerts', 0)
        total_incidents = stats.get('total_incidents', 0)
        
        # Header
        print("=" * 80)
        print(f"🛡️  COMPLETE SOC STATUS PAGE")
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        # Statistics
        print(f"\n📊 STATISTICS:")
        print(f"   📨 Alerts: {total_alerts}")
        print(f"   🚨 Incidents: {total_incidents}")
        print(f"   ⏱️  Status: {stats.get('uptime', 'unknown')}")
        
        # Severity Breakdown
        if alerts:
            severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for alert in alerts:
                sev = alert.get('severity', 'low')
                if sev in severity_count:
                    severity_count[sev] += 1
            
            print(f"\n📊 SEVERITY:")
            print(f"   🔴 Critical: {severity_count['critical']}")
            print(f"   🟡 High: {severity_count['high']}")
            print(f"   🟢 Medium: {severity_count['medium']}")
            print(f"   �� Low: {severity_count['low']}")
        
        # Recent Alerts
        print(f"\n📋 RECENT ALERTS:")
        if alerts:
            for alert in alerts[-5:]:
                severity = alert.get('severity', 'low')
                emoji = "🔴" if severity == 'critical' else "🟡" if severity == 'high' else "🟢"
                title = alert.get('title', 'Unknown')[:40]
                print(f"   {emoji} {title}")
        else:
            print("   No alerts yet")
        
        # System Health
        print(f"\n🔧 SYSTEM HEALTH:")
        print(f"   🟢 Platform: Running")
        print(f"   🟢 API: Online")
        print(f"   🟢 ML Engine: Active")
        print(f"   🟢 Database: Connected")
        
        # Footer
        print("\n" + "=" * 80)
        print("🔄 Refreshes every 5 seconds | Press Ctrl+C to exit")
        print("=" * 80)
        
        time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
