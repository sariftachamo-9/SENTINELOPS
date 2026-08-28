#!/usr/bin/env python3
"""
Automated Alert Response System
"""

import requests
import json
from datetime import datetime
import time

def get_critical_alerts():
    """Get all critical alerts"""
    try:
        r = requests.get("http://localhost:8001/api/alerts", timeout=2)
        alerts = r.json().get('alerts', [])
        return [a for a in alerts if a.get('severity') == 'critical']
    except:
        return []

def block_ip(ip):
    """Block an IP address"""
    print(f"🚫 Blocking IP: {ip}")
    # Add your firewall integration here
    # Example: iptables -A INPUT -s {ip} -j DROP

def isolate_host(host):
    """Isolate a host"""
    print(f"🔒 Isolating host: {host}")
    # Add your host isolation logic here

def send_alert(alert):
    """Send alert notification"""
    print(f"📢 Sending alert: {alert.get('title')}")

def auto_respond():
    """Automated response to critical alerts"""
    print("🔍 Scanning for critical alerts...")
    
    critical_alerts = get_critical_alerts()
    
    if critical_alerts:
        print(f"🚨 Found {len(critical_alerts)} critical alerts!")
        
        for alert in critical_alerts[-5:]:  # Process last 5
            title = alert.get('title', 'Unknown')
            description = alert.get('description', '')
            
            print(f"\n📌 Processing: {title}")
            
            # Auto-respond based on alert type
            if "Malware" in title or "Ransomware" in title:
                print("  ⚡ Malware detected - Initiating quarantine...")
                if 'host' in description:
                    isolate_host(description.split('host')[1].strip().split()[0])
                send_alert(alert)
                
            elif "Exfiltration" in title:
                print("  ⚡ Data exfiltration detected - Blocking IP...")
                if 'src_ip' in description:
                    ip = description.split('src_ip')[1].strip().split()[0]
                    block_ip(ip)
                send_alert(alert)
                
            elif "Port Scan" in title:
                print("  ⚡ Port scan detected - Adding to blocklist...")
                if 'src_ip' in description:
                    ip = description.split('src_ip')[1].strip().split()[0]
                    block_ip(ip)
                    
            else:
                print(f"  ⚡ Alert type: {title}")
                send_alert(alert)
    
    else:
        print("✅ No critical alerts found")

if __name__ == "__main__":
    print("=" * 60)
    print("🤖 Automated Alert Response System")
    print("=" * 60)
    
    while True:
        auto_respond()
        print("\n⏳ Waiting 60 seconds...")
        time.sleep(60)
