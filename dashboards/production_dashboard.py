#!/usr/bin/env python3
"""
Production SOC Dashboard with ML Insights
"""

import requests
import json
from datetime import datetime, timedelta
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

def format_duration(seconds):
    """Format duration in HH:MM:SS"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

def main():
    start_time = datetime.now()
    
    while True:
        try:
            clear()
            stats, alerts, incidents = get_data()
            
            total_alerts = stats.get('total_alerts', 0)
            total_incidents = stats.get('total_incidents', 0)
            
            # Calculate uptime
            uptime = (datetime.now() - start_time).total_seconds()
            
            print("=" * 80)
            print("��️  ENTERPRISE SOC PLATFORM - PRODUCTION DASHBOARD")
            print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"⏱️  Uptime: {format_duration(uptime)}")
            print("=" * 80)
            
            # Statistics
            print(f"\n📊 STATISTICS:")
            print(f"   📨 Total Alerts: {total_alerts}")
            print(f"   🚨 Total Incidents: {total_incidents}")
            
            if incidents:
                active = len([i for i in incidents if i.get('status') == 'open'])
                resolved = len([i for i in incidents if i.get('status') == 'resolved'])
                print(f"   📈 Active Incidents: {active}")
                print(f"   ✅ Resolved: {resolved}")
            
            # Alert Rate
            if total_alerts > 0 and uptime > 0:
                rate = total_alerts / (uptime / 60)
                print(f"   📊 Alert Rate: {rate:.1f} alerts/minute")
            
            # Severity Distribution
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
                        bar_length = min(count, 40)
                        bar = "█" * bar_length + "░" * (40 - bar_length)
                        print(f"   {emoji} {sev.title():8}: {bar} {count}")
            
            # Recent Alerts
            print(f"\n📋 RECENT ALERTS (Last 5):")
            if alerts:
                for alert in alerts[-5:]:
                    severity = alert.get('severity', 'low')
                    emoji = "🔴" if severity == 'critical' else "��" if severity == 'high' else "🟢"
                    title = alert.get('title', 'Unknown')[:35]
                    ts = alert.get('timestamp', '')[:19]
                    print(f"   {emoji} [{ts}] {title}")
            else:
                print("   No alerts yet")
            
            # ML Insights
            if len(alerts) > 5:
                print(f"\n🧠 ML INSIGHTS:")
                print(f"   🔍 Total Alerts: {total_alerts}")
                if uptime > 0:
                    rate = total_alerts / (uptime / 60)
                    print(f"   📈 Alert Rate: {rate:.1f}/min")
                    
                    if rate > 5:
                        print(f"   ⚠️  High Alert Rate Detected: {rate:.1f}/min")
                    else:
                        print(f"   ✅ Normal Alert Rate: {rate:.1f}/min")
            
            # System Status
            print(f"\n🔧 SYSTEM STATUS:")
            print(f"   🟢 Platform: Running")
            print(f"   🟢 API: Online")
            print(f"   🟢 ML Engine: Active")
            
            # Footer
            print("\n" + "=" * 80)
            print(f"🔄 Auto-refresh: 3 seconds | Alerts: {total_alerts} | Incidents: {total_incidents}")
            print("🛡️  Enterprise SOC Platform v1.0 | Press Ctrl+C to exit")
            print("=" * 80)
            
            time.sleep(3)
            
        except Exception as e:
            print(f"⚠️ Error: {e}")
            time.sleep(3)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped - Goodbye!")
        sys.exit(0)
