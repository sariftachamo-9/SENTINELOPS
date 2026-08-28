import json
import re
from datetime import datetime
from collections import defaultdict
from src.detection_engine import DetectionEngine

class AlertRulesEngine:
    """
    Wrapper around DetectionEngine for backward compatibility with Phase 1-4 modules.
    """
    def __init__(self, db=None):
        self.engine = DetectionEngine(db=db)
        self.event_history = defaultdict(list)

    @property
    def rules(self):
        return self.engine.get_all_rules()

    def evaluate_event(self, event):
        matches = self.engine.evaluate_event(event)
        alerts = []
        now_str = datetime.now().isoformat()
        
        for match in matches:
            alert = {
                'id': f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{match['rule_id']}",
                'rule_id': match['rule_id'],
                'title': match['title'],
                'severity': match['severity'],
                'description': match['description'],
                'reason': match.get('reason', ''),
                'source': match.get('source', 'unknown'),
                'destination': match.get('destination', '0.0.0.0'),
                'affected_asset': match.get('affected_asset', 'unknown'),
                'affected_user': match.get('affected_user', 'System'),
                'mitre_tactic': match.get('mitre_tactic', 'Execution'),
                'mitre_technique': match.get('mitre_technique', 'T1059'),
                'mitre_technique_id': match.get('mitre_technique_id', 'T1059'),
                'mitre_technique_name': match.get('mitre_technique_name', 'Execution'),
                'detection_rule': match['title'],
                'confidence': match.get('confidence', 85),
                'timestamp': now_str,
                'indicators': [match.get('source'), event.get('process_name') or event.get('event_type')],
                'triggering_event_ids': match.get('triggering_event_ids', []),
                'evidence': match.get('evidence', []),
                'raw_event': event
            }
            alerts.append(alert)
        return alerts

    def _check_rule(self, rule, event):
        return self.engine._matches_conditions(rule, event)
