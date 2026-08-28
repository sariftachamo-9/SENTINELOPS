import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import json

class MLAnomalyDetector:
    """
    Assistive Behavioral & Anomaly Detection Model
    Produces explainable outputs with explicit reasons and confidence ratings.
    """
    def __init__(self):
        self.model_version = "v1.2.0-IsolationForest"
        self.scaler = StandardScaler()
        self.features = ['bytes', 'src_port', 'dst_port', 'event_type_freq', 'auth_fail_freq']
        self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        self.is_trained = False
        self._init_baseline()

    def _init_baseline(self):
        # Baseline training data
        baseline_data = [
            [500, 49152, 443, 1, 0],
            [1200, 49153, 80, 1, 0],
            [450, 49154, 443, 1, 0],
            [800, 49155, 53, 2, 0],
            [600, 49156, 443, 1, 0],
            [500000, 49157, 22, 10, 5], # Anomaly candidate
            [350, 49158, 443, 1, 0],
            [900, 49159, 80, 1, 0]
        ]
        X = np.array(baseline_data)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

    def detect(self, event: dict) -> dict:
        """
        Detect if an event is anomalous and produce clear explainable reasons.
        """
        bytes_val = float(event.get('size') or event.get('bytes_out') or event.get('bytes', 500))
        src_port = float(event.get('source_port') or event.get('src_port', 49152))
        dst_port = float(event.get('destination_port') or event.get('dst_port', 80))
        event_freq = float(event.get('occurrence_count', 1))
        auth_fail = 1.0 if 'Failed' in str(event.get('event_type', '')) or 'brute' in str(event.get('title', '')).lower() else 0.0

        feat_vector = [bytes_val, src_port, dst_port, event_freq, auth_fail]
        X = np.array([feat_vector])
        X_scaled = self.scaler.transform(X)

        raw_score = float(self.model.decision_function(X_scaled)[0])
        is_anomaly = bool(self.model.predict(X_scaled)[0] == -1)

        # Convert decision function score to normalized [0.0, 1.0] anomaly score
        anomaly_score = round(min(max(0.5 - raw_score, 0.0), 1.0), 3)
        confidence = round(min(0.65 + (anomaly_score * 0.35), 0.99), 2)

        reasons = []
        if bytes_val > 100000:
            reasons.append(f"Unusually large payload size ({int(bytes_val)} bytes)")
        if dst_port in [22, 3389, 445]:
            reasons.append(f"Sensitive administrative port accessed (Port {int(dst_port)})")
        if auth_fail > 0:
            reasons.append("Unusual authentication failure frequency")
        if event_freq > 5:
            reasons.append(f"High event execution velocity ({int(event_freq)} occurrences)")

        if is_anomaly and not reasons:
            reasons.append("Multi-dimensional feature vector deviation from historical baseline")

        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'confidence': confidence,
            'reasons': reasons if reasons else ["Normal baseline pattern"],
            'features': {
                'bytes': bytes_val,
                'src_port': src_port,
                'dst_port': dst_port,
                'event_type_freq': event_freq,
                'auth_fail_freq': auth_fail
            },
            'model_version': self.model_version
        }
