#!/usr/bin/env python3
"""
Generate realistic security alerts for testing
"""

import requests
import json
import random
import time
from datetime import datetime

# Realistic alert templates
ALERT_TEMPLATES = [
    {
        "title": "Port Scan Detected",
        "severity": "high",
        "description": "Multiple ports scanned from {src_ip} targeting {dst_ip}",
        "src_ip": "192.168.1.{ip}",
        "dst_ip": "10.0.0.{ip}"
    },
    {
        "title": "Failed Login Attempts",
        "severity": "medium",
        "description": "{count} failed login attempts from {src_ip} to {dst_ip}",
        "src_ip": "192.168.1.{ip}",
        "dst_ip": "10.0.0.{ip}"
    },
    {
        "title": "Malware Signature Detected",
        "severity": "critical",
        "description": "Malware signature '{signature}' detected on host {host}",
        "host": "host-{id}",
        "signature": "Trojan.Generic.{id}"
    },
    {
        "title": "Data Exfiltration Attempt",
        "severity": "critical",
        "description": "Large data transfer detected from {src_ip} to external IP {dst_ip}",
        "src_ip": "192.168.1.{ip}",
        "dst_ip": "8.8.8.{ip}"
    },
    {
        "title": "Suspicious Process Execution",
        "severity": "high",
        "description": "Suspicious process '{process}' executed on host {host}",
        "host": "host-{id}",
        "process": "powershell.exe -e {encoded}"
    },
    {
        "title": "DNS Tunneling Detected",
        "severity": "high",
        "description": "DNS tunneling activity detected from {src_ip} to {domain}",
        "src_ip": "192.168.1.{ip}",
        "domain": "malicious-{id}.com"
    },
    {
        "title": "Ransomware Activity",
        "severity": "critical",
        "description": "Ransomware activity detected on host {host} - files encrypted",
        "host": "host-{id}"
    },
    {
        "title": "Privilege Escalation Attempt",
        "severity": "high",
        "description": "Privilege escalation attempt detected on host {host} by user {user}",
        "host": "host-{id}",
        "user": "user-{id}"
    }
]

def generate_alert():
    """Generate a realistic security alert tagged clearly for lab simulation"""
    template = random.choice(ALERT_TEMPLATES)
    src_ip = f"192.168.1.{random.randint(1,254)}"
    alert = {
        "title": template["title"],
        "severity": template["severity"],
        "description": template["description"].format(
            src_ip=src_ip,
            dst_ip=f"10.0.0.{random.randint(1,254)}",
            ip=random.randint(1,254),
            id=random.randint(100,999),
            count=random.randint(5,50),
            host=f"host-{random.randint(1,50)}",
            signature=f"Trojan.Generic.{random.randint(1000,9999)}",
            process=f"powershell.exe -e {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=20))}",
            domain=f"malicious-{random.randint(1,999)}.com",
            user=f"user-{random.randint(1,100)}",
            encoded=''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=', k=random.randint(10,30)))
        ),
        "source": "simulation",
        "environment": "lab",
        "indicators": [src_ip, template["title"]]
    }
    return alert

def send_alerts(count=10, delay=1):
    """Send multiple alerts to the SOC platform"""
    print(f"📨 Sending {count} realistic alerts...")
    
    for i in range(count):
        alert = generate_alert()
        try:
            response = requests.post(
                "http://localhost:8001/api/alerts",
                json=alert,
                timeout=5
            )
            if response.status_code == 200:
                print(f"  ✅ Alert {i+1}: {alert['title']} ({alert['severity']})")
            else:
                print(f"  ❌ Alert {i+1} failed: {response.status_code}")
        except Exception as e:
            print(f"  ❌ Alert {i+1} error: {e}")
        
        time.sleep(delay)
    
    print("✅ All alerts sent!")

if __name__ == "__main__":
    import sys
    print("=" * 60)
    print("🛡️  Realistic Alert Generator")
    print("=" * 60)
    
    if "--continuous" in sys.argv:
        print("🔄 Continuous alert generation active...")
        try:
            while True:
                send_alerts(count=5, delay=0.8)
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n👋 Alert generator stopped.")
    else:
        # Send 20 alerts with realistic patterns
        send_alerts(count=20, delay=0.5)
        print(f"\n📊 Check your dashboard now!")
        print(f"🔗 http://localhost:8001/api/stats")
