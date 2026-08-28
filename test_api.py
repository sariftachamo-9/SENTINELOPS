import requests
import json
import time

print("=" * 60)
print("SOC Platform API Test")
print("=" * 60)

BASE_URL = "http://localhost:8001"

def test_health():
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"✓ Health: {r.status_code}")
        print(f"  {r.json()}")
        return True
    except Exception as e:
        print(f"✗ Health: {e}")
        return False

def test_create_alerts():
    print("\n📨 Sending test alerts...")
    alerts_sent = 0
    for i in range(3):
        try:
            alert = {
                "title": f"Test Alert #{i+1}",
                "severity": "high" if i % 2 == 0 else "medium",
                "description": f"This is test alert number {i+1}",
                "source": "test_script",
                "indicators": [f"192.168.1.{100+i}"]
            }
            r = requests.post(f"{BASE_URL}/api/alerts", json=alert, timeout=5)
            if r.status_code == 200:
                alerts_sent += 1
                print(f"  ✓ Alert {i+1} sent: {r.json().get('alert_id')}")
        except Exception as e:
            print(f"  ✗ Alert {i+1} failed: {e}")
        time.sleep(0.5)
    print(f"✅ Sent {alerts_sent} alerts")

def test_get_stats():
    try:
        r = requests.get(f"{BASE_URL}/api/stats", timeout=5)
        print(f"\n�� Stats: {r.status_code}")
        data = r.json()
        print(f"  Total alerts: {data.get('total_alerts', 0)}")
        print(f"  Total incidents: {data.get('total_incidents', 0)}")
        print(f"  Events: {data.get('events_processed', 0)}")
        return data
    except Exception as e:
        print(f"✗ Stats: {e}")
        return None

def test_get_alerts():
    try:
        r = requests.get(f"{BASE_URL}/api/alerts", timeout=5)
        print(f"\n📋 Alerts: {r.status_code}")
        data = r.json()
        # API returns a list directly
        if isinstance(data, list):
            alerts = data
        else:
            alerts = data.get('alerts', [])
        print(f"  Total alerts in response: {len(alerts)}")
        if alerts:
            latest = alerts[0]
            print(f"  Latest: [{latest.get('severity','?').upper()}] {latest.get('title','?')}")
        return data
    except Exception as e:
        print(f"✗ Alerts: {e}")
        return None

if __name__ == "__main__":
    print("Waiting for API to start...")
    for i in range(10):
        if test_health():
            break
        time.sleep(1)
    
    time.sleep(2)  # Wait for background generator to create some data
    test_get_stats()
    test_get_alerts()
    test_create_alerts()
    time.sleep(2)
    test_get_stats()
    print("\n" + "=" * 60)
    print("✅ Test complete! Check your dashboard now.")
    print("=" * 60)
