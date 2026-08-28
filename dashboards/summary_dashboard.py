#!/usr/bin/env python3
"""
SOC Summary Dashboard - Quick Overview
"""

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
    print("=" * 60)
    print("⚡ SOC STATUS SUMMARY")
    print("=" * 60)
    
    while True:
        clear()
        stats, alerts, incidents = get_data()
        
        total_alerts = stats.get('total_alerts', 0)
        total_incidents = stats.get('total_incidents', 0)
        
        # Header
        print("=" * 60)
        print(f"⚡ SOC STATUS | {datetime.now().strftime('%H:%M:%S')}")
        print("=" * 60)
        
        # Quick Stats
        print(f"📨 Alerts: {total_alerts}")
        print(f"🚨 Incidents: {total_incidents}")
        print(f"⏱️  Status: {stats.get('uptime', 'unknown')}")
        
        # Severity Quick View
        if alerts:
            critical = len([a for a in alerts if a.get('severity') == 'critical'])
            high = len([a for a in alerts if a.get('severity') == 'high'])
            medium = len([a for a in alerts if a.get('severity') == 'medium'])
            
            print(f"\n🔴 Critical: {critical}")
            print(f"🟡 High: {high}")
            print(f"🟢 Medium: {medium}")
            
            # Health bar
            total = len(alerts)
            if total > 0:
                health = int((total - critical - high) / total * 100)
                bar = "█" * health + "░" * (100 - health)
                print(f"\nHealth: [{bar}] {health}%")
        
        print("\n" + "=" * 60)
        time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
