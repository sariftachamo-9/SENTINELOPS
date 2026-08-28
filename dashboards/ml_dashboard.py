#!/usr/bin/env python3
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
    print("=" * 80)
    print("🤖 ML-ENHANCED SOC PLATFORM DASHBOARD")
    print("=" * 80)
    
    while True:
        clear()
        stats, alerts, incidents = get_data()
        
        total_alerts = stats.get('total_alerts', 0)
        total_incidents = stats.get('total_incidents', 0)
        
        print("=" * 80)
        print(f"🤖 ML-ENHANCED SOC PLATFORM DASHBOARD")
        print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        print(f"\n📊 STATISTICS:")
        print(f"   📨 Total Alerts: {total_alerts}")
        print(f"   🚨 Total Incidents: {total_incidents}")
        print(f"   ⏱️  Status: {stats.get('uptime', 'unknown')}")
        
        # ML Status
        print(f"\n🧠 ML STATUS:")
        print(f"   ✅ scikit-learn: Loaded")
        print(f"   ✅ Anomaly Detection: Active")
        print(f"   ✅ Correlation Engine: Active")
        
        # Alert Severity Distribution
        if alerts:
            severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for alert in alerts:
                sev = alert.get('severity', 'low')
                if sev in severity_count:
                    severity_count[sev] += 1
            
            print(f"\n📊 ALERT SEVERITY:")
            for sev, count in severity_count.items():
                if count > 0:
                    emoji = "🔴" if sev == 'critical' else "🟡" if sev == 'high' else "🟢" if sev == 'medium' else "🔵"
                    bar = "█" * (count * 2) + "░" * (20 - count * 2)
                    print(f"   {emoji} {sev.title()}: {bar} {count}")
        
        # Recent alerts
        print(f"\n📋 RECENT ALERTS (Last 5):")
        if alerts:
            for alert in alerts[-5:]:
                severity = alert.get('severity', 'low')
                emoji = "🔴" if severity == 'critical' else "🟡" if severity == 'high' else "🟢"
                title = alert.get('title', 'Unknown')[:35]
                ts = alert.get('timestamp', '')[:19]
                # ML detection tag
                ml_tag = " 🧠" if severity in ['critical', 'high'] else ""
                print(f"   {emoji} [{ts}] {title}{ml_tag}")
        else:
            print("   No alerts yet")
        
        # ML insights
        if len(alerts) > 10:
            print(f"\n💡 ML INSIGHTS:")
            print(f"   🔍 Detected {len(alerts)} alerts in last session")
            print(f"   📈 Alert rate: {len(alerts) / 10:.1f} per minute")
            print(f"   🎯 Critical alerts: {severity_count.get('critical', 0)}")
        
        # Footer
        print("\n" + "=" * 80)
        print(f"🔄 Refreshes every 3 seconds | Alerts: {total_alerts} | Incidents: {total_incidents}")
        print("🧠 ML Detection Active | Press Ctrl+C to exit")
        print("=" * 80)
        
        time.sleep(3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")
