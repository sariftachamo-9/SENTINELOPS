#!/usr/bin/env python3
"""
Continuous Alert Generator for Production
"""

import requests
import random
import time
import sys
from datetime import datetime

ALERT_TYPES = [
    {"title": "Port Scan Detected", "severity": "high"},
    {"title": "Malware Signature Found", "severity": "critical"},
    {"title": "Failed Login Attempts", "severity": "medium"},
    {"title": "Data Exfiltration", "severity": "critical"},
    {"title": "Ransomware Activity", "severity": "critical"},
    {"title": "Privilege Escalation", "severity": "high"},
    {"title": "DNS Tunneling", "severity": "high"},
    {"title": "Suspicious Process", "severity": "high"},
]

def generate_alert():
    alert_type = random.choice(ALERT_TYPES)
    ip1 = f"192.168.1.{random.randint(1,254)}"
    ip2 = f"10.0.0.{random.randint(1,254)}"
    host = f"host-{random.randint(1,50)}"
    
    descriptions = {
        "Port Scan Detected": f"Port scan from {ip1} targeting {ip2}",
        "Malware Signature Found": f"Trojan.Generic.{random.randint(1000,9999)} on {host}",
        "Failed Login Attempts": f"{random.randint(5,50)} failed logins from {ip1} to {ip2}",
        "Data Exfiltration": f"Large data transfer from {ip1} to external IP {ip2}",
        "Ransomware Activity": f"Ransomware detected on {host} - files encrypted",
        "Privilege Escalation": f"User user-{random.randint(1,100)} attempted escalation on {host}",
        "DNS Tunneling": f"DNS tunneling from {ip1} to malicious-{random.randint(100,999)}.com",
        "Suspicious Process": f"Process 'powershell.exe -e {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=20))}' on {host}",
    }
    
    return {
        "title": alert_type["title"],
        "severity": alert_type["severity"],
        "description": descriptions.get(alert_type["title"], "Security alert detected")
    }

def send_alert(alert):
    try:
        response = requests.post(
            "http://localhost:8001/api/alerts",
            json=alert,
            timeout=2
        )
        return response.status_code == 200
    except:
        return False

def main():
    print("🔄 Continuous Alert Generator Started")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    count = 0
    while True:
        alert = generate_alert()
        if send_alert(alert):
            count += 1
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ Alert #{count}: {alert['title']} ({alert['severity']})")
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Failed to send alert")
        
        time.sleep(random.uniform(0.5, 1.5))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Alert generator stopped")
        sys.exit(0)
