#!/usr/bin/env python3
import sqlite3
import json
import shutil
import os
from datetime import datetime

def backup_database():
    """Backup the SQLite database"""
    backup_dir = "backups"
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = f"{backup_dir}/soc_data_{timestamp}.db"
    
    # Copy database
    shutil.copy2('soc_data.db', backup_file)
    
    # Export to JSON
    conn = sqlite3.connect('soc_data.db')
    cursor = conn.cursor()
    
    # Export alerts
    cursor.execute("SELECT * FROM alerts")
    alerts = cursor.fetchall()
    
    # Export incidents
    cursor.execute("SELECT * FROM incidents")
    incidents = cursor.fetchall()
    
    conn.close()
    
    # Save JSON backup
    json_file = f"{backup_dir}/soc_data_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump({
            'timestamp': timestamp,
            'alerts': alerts,
            'incidents': incidents
        }, f, default=str)
    
    print(f"✅ Backup created: {backup_file}")
    print(f"✅ JSON export: {json_file}")
    return backup_file

if __name__ == "__main__":
    backup_database()
