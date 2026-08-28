import requests
import json
from datetime import datetime

class Notifications:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url
    
    def send_slack(self, alert):
        if not self.webhook_url:
            print("No Slack webhook configured")
            return
        
        emoji = "🔴" if alert.get('severity') == 'critical' else "🟡" if alert.get('severity') == 'high' else "🟢"
        message = {
            "text": f"{emoji} *{alert.get('title')}*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *ALERT: {alert.get('title')}*\n"
                               f"Severity: {alert.get('severity')}\n"
                               f"Time: {alert.get('timestamp')}\n"
                               f"Description: {alert.get('description')}"
                    }
                }
            ]
        }
        
        try:
            response = requests.post(self.webhook_url, json=message)
            if response.status_code == 200:
                print(f"✅ Slack notification sent for {alert.get('id')}")
            else:
                print(f"❌ Slack notification failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Slack error: {e}")
    
    def send_email(self, alert):
        # Email implementation
        pass

# Slack webhook URL must be set via SLACK_WEBHOOK_URL environment variable.
# Example: export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
# Do NOT hard-code webhook URLs here.
