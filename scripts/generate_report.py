#!/usr/bin/env python3
"""
Generate SOC Platform Performance Report
"""

import requests
import json
from datetime import datetime

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

def get_incidents():
    try:
        r = requests.get("http://localhost:8001/api/incidents", timeout=2)
        data = r.json()
        return data.get('incidents', [])
    except:
        return []

def generate_report():
    stats = get_stats()
    alerts = get_alerts()
    incidents = get_incidents()
    
    print("=" * 70)
    print("📊 SOC PLATFORM PERFORMANCE REPORT")
    print(f"📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    # Summary
    print(f"\n📈 SUMMARY:")
    print(f"   Total Alerts: {stats.get('total_alerts', 0)}")
    print(f"   Total Incidents: {stats.get('total_incidents', 0)}")
    print(f"   Status: {stats.get('uptime', 'unknown')}")
    print(f"   Started: {stats.get('start_time', 'unknown')}")
    
    # Alert Statistics
    if alerts:
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for alert in alerts:
            sev = alert.get('severity', 'low')
            if sev in severity_count:
                severity_count[sev] += 1
        
        print(f"\n📊 ALERT SEVERITY DISTRIBUTION:")
        for sev, count in severity_count.items():
            if count > 0:
                percentage = (count / len(alerts)) * 100
                print(f"   {sev.title():8}: {count:3} ({percentage:5.1f}%)")
    
    # Incident Statistics
    if incidents:
        status_count = {'open': 0, 'resolved': 0, 'closed': 0}
        for inc in incidents:
            status = inc.get('status', 'open')
            if status in status_count:
                status_count[status] += 1
        
        print(f"\n🚨 INCIDENT STATUS:")
        for status, count in status_count.items():
            if count > 0:
                percentage = (count / len(incidents)) * 100
                print(f"   {status.title():8}: {count:3} ({percentage:5.1f}%)")
    
    # Recent Activity
    print(f"\n📋 RECENT ACTIVITY:")
    if alerts:
        latest = alerts[-3:]
        print(f"   Last 3 Alerts:")
        for alert in latest:
            print(f"     • {alert.get('title', 'Unknown')} ({alert.get('severity', 'low')})")
    else:
        print("   No recent alerts")
    
    print("\n" + "=" * 70)
    print("✅ Report Generated")
    print("=" * 70)

if __name__ == "__main__":
    generate_report()
