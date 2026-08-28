#!/usr/bin/env python3
"""
Initial Setup Script for SOC Platform
"""

import os
import sys
import json
import yaml
import sqlite3
import subprocess
from pathlib import Path
import shutil
import hashlib
import secrets
import string
from datetime import datetime
import requests

def setup_environment():
    """Setup environment and directories"""
    print("Setting up SOC Platform environment...")
    
    # Create directories
    dirs = [
        'logs', 'data', 'backup', 
        'config/rules', 'config/playbooks',
        'config/threat_intel', 'models'
    ]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    # Create logs
    log_files = ['soc_platform.log', 'structured.log', 'access.log']
    for log_file in log_files:
        Path(f'logs/{log_file}').touch()
    
    print("✓ Directory structure created")

def setup_database():
    """Initialize SQLite database"""
    print("Initializing database...")
    
    conn = sqlite3.connect('soc_data.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,
            source TEXT,
            data JSON,
            processed BOOLEAN DEFAULT FALSE
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            alert_id TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            data JSON,
            status TEXT DEFAULT 'open'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            title TEXT,
            severity TEXT,
            status TEXT,
            playbook TEXT,
            data JSON,
            resolved_at TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE,
            type TEXT,
            severity INTEGER,
            confidence INTEGER,
            source TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            metadata JSON
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            action TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            result JSON
        )
    ''')
    
    conn.commit()
    conn.close()
    
    print("✓ Database initialized")

def setup_initial_rules():
    """Create initial detection and correlation rules"""
    print("Setting up initial rules...")
    
    # Detection Rules
    detection_rules = {
        "rules": [
            {
                "id": "DET-001",
                "name": "SQL Injection Attempt",
                "severity": "high",
                "type": "signature",
                "pattern": "(select|insert|update|delete|drop|union|exec|declare).*",
                "fields": ["url", "body", "params"],
                "response": {
                    "action": "block_request",
                    "notify": True
                }
            },
            {
                "id": "DET-002",
                "name": "XSS Attack Attempt",
                "severity": "high",
                "type": "signature",
                "pattern": "<script.*>|javascript:|onerror=|onload=",
                "fields": ["url", "body", "params"],
                "response": {
                    "action": "block_request",
                    "notify": True
                }
            },
            {
                "id": "DET-003",
                "name": "Potential Data Exfiltration",
                "severity": "critical",
                "type": "statistical",
                "threshold": {
                    "field": "bytes_out",
                    "value": 1000000,
                    "time_window": 60
                },
                "response": {
                    "action": "isolate_host",
                    "notify": True
                }
            }
        ]
    }
    
    with open('config/rules/detection_rules.json', 'w') as f:
        json.dump(detection_rules, f, indent=2)
    
    # Correlation Rules
    correlation_rules = {
        "rules": [
            {
                "id": "CORR-001",
                "name": "Failed Login Sequence",
                "type": "sequence",
                "sequence": [
                    {"event_type": "failed_login", "count": 1},
                    {"event_type": "successful_login", "count": 1},
                    {"event_type": "privilege_escalation", "count": 1}
                ],
                "max_gap": 300,
                "severity": "high"
            },
            {
                "id": "CORR-002",
                "name": "Port Scan Detection",
                "type": "pattern",
                "pattern": {
                    "feature_fields": ["src_ip", "dst_port"],
                    "min_cluster_size": 10
                },
                "severity": "medium"
            }
        ]
    }
    
    with open('config/rules/correlation_rules.json', 'w') as f:
        json.dump(correlation_rules, f, indent=2)
    
    print("✓ Initial rules created")

def setup_playbooks():
    """Create initial playbooks"""
    print("Setting up response playbooks...")
    
    playbooks = {
        "ransomware": {
            "id": "ransomware",
            "name": "Ransomware Response Playbook",
            "severity": "critical",
            "triggers": [
                {"type": "signature", "value": "encrypted_files"},
                {"type": "indicator", "value": "ransomware_hash"}
            ],
            "steps": [
                {"action": "isolate_host", "timeout": 60},
                {"action": "kill_process", "timeout": 30},
                {"action": "capture_forensics", "timeout": 300},
                {"action": "notify_team", "params": {"channels": ["security", "management"]}},
                {"action": "create_case", "params": {"severity": "critical"}}
            ]
        },
        "phishing": {
            "id": "phishing",
            "name": "Phishing Response Playbook",
            "severity": "high",
            "triggers": [
                {"type": "indicator", "value": "phishing_email"},
                {"type": "signature", "value": "suspicious_url"}
            ],
            "steps": [
                {"action": "block_ip", "timeout": 60},
                {"action": "revoke_access", "params": {"temporary": True}},
                {"action": "reset_credentials", "timeout": 120},
                {"action": "notify_team", "params": {"channels": ["security", "it"]}}
            ]
        }
    }
    
    for name, playbook in playbooks.items():
        with open(f'config/playbooks/{name}.yml', 'w') as f:
            yaml.dump(playbook, f, default_flow_style=False)
    
    print("✓ Playbooks created")

def generate_ssl_cert():
    """Generate SSL certificate for development"""
    print("Generating SSL certificate...")
    
    # Check if openssl is installed
    if subprocess.run(['which', 'openssl'], capture_output=True).returncode != 0:
        print("⚠ OpenSSL not found. Skipping SSL certificate generation.")
        return
    
    # Generate private key and certificate
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', 'key.pem', '-out', 'cert.pem',
        '-days', '365', '-nodes',
        '-subj', '/CN=localhost/O=SOC/C=US'
    ])
    
    print("✓ SSL certificates generated")

def main():
    """Main setup function"""
    print("=" * 60)
    print("SOC Platform Setup")
    print("=" * 60)
    
    try:
        setup_environment()
        setup_database()
        setup_initial_rules()
        setup_playbooks()
        generate_ssl_cert()
        
        print("\n" + "=" * 60)
        print("Setup Complete!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Update environment variables in .env file")
        print("2. Start services:")
        print("   - docker-compose up -d")
        print("3. Run the SOC platform:")
        print("   - source venv/bin/activate")
        print("   - python src/main.py")
        print("4. Access Kibana: http://localhost:5601")
        print("5. Access Grafana: http://localhost:3000")
        print("\nDefault credentials:")
        print("   Elasticsearch: elastic / password (set in .env)")
        print("   Grafana: admin / password (set in .env)")
        print("   TheHive: admin / admin (set your own password)")
        print("\n" + "=" * 60)
        
    except Exception as e:
        print(f"❌ Setup failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()