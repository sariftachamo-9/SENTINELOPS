import json
import os
import requests
from typing import List, Dict, Any

class SIEMAdapter:
    """Base Adapter Interface for SIEM / Telemetry Sources"""
    def __init__(self, name: str):
        self.name = name

    def check_health(self) -> Dict[str, Any]:
        return {"adapter": self.name, "status": "OFFLINE", "details": "Not configured"}

    def fetch_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        return []

class WazuhAdapter(SIEMAdapter):
    def __init__(self, api_url: str = None, api_user: str = "wazuh", api_pass: str = "wazuh"):
        super().__init__("Wazuh")
        self.api_url = api_url or os.getenv("WAZUH_API_URL", "https://localhost:55000")
        self.user = api_user
        self.password = api_pass

    def check_health(self) -> Dict[str, Any]:
        if not self.api_url or self.api_url.startswith("https://localhost"):
            return {"adapter": self.name, "status": "OFFLINE", "details": "Wazuh API endpoint unconfigured"}
        try:
            r = requests.get(f"{self.api_url}/", auth=(self.user, self.password), timeout=2, verify=False)
            if r.status_code == 200:
                return {"adapter": self.name, "status": "ONLINE", "details": "Connected"}
        except Exception as e:
            pass
        return {"adapter": self.name, "status": "OFFLINE", "details": "Unreachable"}

class ElasticAdapter(SIEMAdapter):
    def __init__(self, es_url: str = None):
        super().__init__("Elastic/OpenSearch")
        self.es_url = es_url or os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")

    def check_health(self) -> Dict[str, Any]:
        try:
            r = requests.get(f"{self.es_url}/", timeout=2)
            if r.status_code == 200:
                return {"adapter": self.name, "status": "ONLINE", "details": r.json().get("version", {}).get("number", "ES")}
        except Exception:
            pass
        return {"adapter": self.name, "status": "OFFLINE", "details": "Elasticsearch cluster unreachable"}

class SuricataAdapter(SIEMAdapter):
    def __init__(self, log_path: str = None):
        super().__init__("Suricata IDS")
        self.log_path = log_path or os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json")

    def check_health(self) -> Dict[str, Any]:
        if os.path.exists(self.log_path):
            return {"adapter": self.name, "status": "ONLINE", "details": f"Reading {self.log_path}"}
        return {"adapter": self.name, "status": "OFFLINE", "details": f"File {self.log_path} not present"}

class ZeekAdapter(SIEMAdapter):
    def __init__(self, log_dir: str = None):
        super().__init__("Zeek NSM")
        self.log_dir = log_dir or os.getenv("ZEEK_LOG_DIR", "/var/log/zeek/current")

    def check_health(self) -> Dict[str, Any]:
        if os.path.exists(self.log_dir):
            return {"adapter": self.name, "status": "ONLINE", "details": f"Monitoring {self.log_dir}"}
        return {"adapter": self.name, "status": "OFFLINE", "details": f"Directory {self.log_dir} not present"}

class SIEMManager:
    def __init__(self):
        self.adapters = [
            WazuhAdapter(),
            ElasticAdapter(),
            SuricataAdapter(),
            ZeekAdapter()
        ]

    def get_all_health(self) -> List[Dict[str, Any]]:
        return [adapter.check_health() for adapter in self.adapters]
