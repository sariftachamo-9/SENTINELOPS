#!/usr/bin/env python3
"""
Advanced Event Correlation Engine with Pattern Detection
"""

import asyncio
from typing import Dict, List, Any, Set, Optional
from datetime import datetime, timedelta
import json
import numpy as np
from collections import defaultdict
import pandas as pd
from scipy.spatial.distance import cosine
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import networkx as nx
import re
import hashlib
import redis
import pickle

class CorrelationEngine:
    """Advanced Event Correlation Engine"""
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        
        # Initialize Redis for caching
        self.redis = redis.Redis(
            host=config.get('redis', {}).get('host', 'localhost'),
            port=config.get('redis', {}).get('port', 6379),
            decode_responses=True
        )
        
        # Correlation rules
        self.rules = self._load_rules()
        
        # Temporal patterns
        self.temporal_patterns = {}
        
        # Graph for relationships
        self.relationship_graph = nx.DiGraph()
        
        # ML models for pattern detection
        self.anomaly_scaler = StandardScaler()
        self.pattern_clusterer = DBSCAN(eps=0.5, min_samples=3)
        
        # Statistics
        self.stats = {
            'correlations_found': 0,
            'patterns_detected': 0,
            'rules_triggered': 0,
            'false_positives': 0
        }
        
        self._load_ml_models()
        self._initialize_graph()
    
    def _load_rules(self) -> List[Dict]:
        """Load correlation rules"""
        try:
            with open('config/rules/correlation_rules.json', 'r') as f:
                return json.load(f)
        except:
            return []
    
    def _load_ml_models(self):
        """Load ML models for pattern detection"""
        try:
            with open('ml_models/correlation_model.pkl', 'rb') as f:
                self.correlation_model = pickle.load(f)
        except:
            self.correlation_model = None
    
    def _initialize_graph(self):
        """Initialize relationship graph"""
        # Add nodes for common entities
        self.relationship_graph.add_nodes_from(['users', 'hosts', 'ips', 'networks'])
    
    async def correlate(self, events: List[Dict]) -> List[Dict]:
        """Main correlation function"""
        correlations = []
        
        try:
            # Apply rules-based correlation
            rule_correlations = self._apply_rules(events)
            correlations.extend(rule_correlations)
            
            # Apply temporal correlation
            temporal_correlations = await self._temporal_correlation(events)
            correlations.extend(temporal_correlations)
            
            # Apply spatial correlation
            spatial_correlations = await self._spatial_correlation(events)
            correlations.extend(spatial_correlations)
            
            # Apply behavioral correlation
            behavioral_correlations = await self._behavioral_correlation(events)
            correlations.extend(behavioral_correlations)
            
            # Apply ML-based correlation
            ml_correlations = await self._ml_correlation(events)
            correlations.extend(ml_correlations)
            
            # Update statistics
            self.stats['correlations_found'] += len(correlations)
            
        except Exception as e:
            self.logger.error(f"Correlation error: {str(e)}")
        
        return correlations
    
    def _apply_rules(self, events: List[Dict]) -> List[Dict]:
        """Apply rule-based correlation"""
        correlations = []
        
        for rule in self.rules:
            try:
                if rule['type'] == 'sequence':
                    correlations.extend(self._detect_sequence(events, rule))
                elif rule['type'] == 'pattern':
                    correlations.extend(self._detect_pattern(events, rule))
                elif rule['type'] == 'threshold':
                    correlations.extend(self._detect_threshold(events, rule))
                elif rule['type'] == 'relationship':
                    correlations.extend(self._detect_relationship(events, rule))
                
                self.stats['rules_triggered'] += 1
                
            except Exception as e:
                self.logger.error(f"Rule {rule.get('name', 'unknown')} error: {str(e)}")
        
        return correlations
    
    def _detect_sequence(self, events: List[Dict], rule: Dict) -> List[Dict]:
        """Detect sequence of events"""
        correlations = []
        sequence = rule['sequence']
        max_gap = rule.get('max_gap', 300)  # seconds
        
        # Group events by correlation key
        grouped = defaultdict(list)
        for event in events:
            key = self._get_correlation_key(event, rule.get('correlation_fields', []))
            if key:
                grouped[key].append(event)
        
        for key, key_events in grouped.items():
            # Sort by timestamp
            key_events.sort(key=lambda x: x.get('timestamp', ''))
            
            # Check for sequence
            for i, start_event in enumerate(key_events):
                # Check if we can complete the sequence
                if len(key_events) - i < len(sequence):
                    break
                
                # Try to match sequence
                matched = True
                for j, event_pattern in enumerate(sequence):
                    if i + j >= len(key_events):
                        matched = False
                        break
                    
                    if not self._matches_pattern(key_events[i + j], event_pattern):
                        matched = False
                        break
                
                if matched:
                    # Check time gap
                    if i + len(sequence) - 1 < len(key_events):
                        start_time = datetime.fromisoformat(key_events[i].get('timestamp'))
                        end_time = datetime.fromisoformat(key_events[i + len(sequence) - 1].get('timestamp'))
                        if (end_time - start_time).total_seconds() <= max_gap:
                            correlations.append({
                                'type': 'sequence',
                                'rule': rule.get('name'),
                                'key': key,
                                'severity': rule.get('severity', 50),
                                'events': key_events[i:i + len(sequence)],
                                'timestamp': datetime.now().isoformat()
                            })
        
        return correlations
    
    def _detect_pattern(self, events: List[Dict], rule: Dict) -> List[Dict]:
        """Detect event patterns"""
        correlations = []
        pattern = rule['pattern']
        
        # Extract features for pattern matching
        features = []
        for event in events:
            feature = self._extract_features(event, pattern.get('feature_fields', []))
            features.append(feature)
        
        # Use DBSCAN for pattern detection
        if features:
            X = np.array(features)
            X_scaled = self.anomaly_scaler.fit_transform(X)
            clusters = self.pattern_clusterer.fit_predict(X_scaled)
            
            # Group events by cluster
            cluster_events = defaultdict(list)
            for i, cluster in enumerate(clusters):
                if cluster != -1:  # -1 means noise
                    cluster_events[cluster].append(events[i])
            
            # Create correlations for each pattern
            for cluster, cluster_events_list in cluster_events.items():
                if len(cluster_events_list) >= rule.get('min_cluster_size', 3):
                    correlations.append({
                        'type': 'pattern',
                        'rule': rule.get('name'),
                        'severity': rule.get('severity', 50),
                        'events': cluster_events_list,
                        'cluster_size': len(cluster_events_list),
                        'timestamp': datetime.now().isoformat()
                    })
                    self.stats['patterns_detected'] += 1
        
        return correlations
    
    def _detect_threshold(self, events: List[Dict], rule: Dict) -> List[Dict]:
        """Detect threshold-based correlations"""
        correlations = []
        threshold = rule.get('threshold', 5)
        time_window = rule.get('time_window', 300)  # seconds
        field = rule.get('field', 'src_ip')
        condition = rule.get('condition', 'count > threshold')
        
        # Group by field
        grouped = defaultdict(list)
        for event in events:
            value = event.get(field)
            if value:
                grouped[value].append(event)
        
        # Check thresholds
        for value, value_events in grouped.items():
            if len(value_events) >= threshold:
                # Check time window
                if time_window:
                    # Sort by timestamp
                    value_events.sort(key=lambda x: x.get('timestamp', ''))
                    
                    # Check sliding window
                    for i in range(len(value_events)):
                        start_time = datetime.fromisoformat(value_events[i].get('timestamp'))
                        end_time = start_time + timedelta(seconds=time_window)
                        
                        window_events = []
                        for j in range(i, len(value_events)):
                            event_time = datetime.fromisoformat(value_events[j].get('timestamp'))
                            if event_time <= end_time:
                                window_events.append(value_events[j])
                            else:
                                break
                        
                        if len(window_events) >= threshold:
                            correlations.append({
                                'type': 'threshold',
                                'rule': rule.get('name'),
                                'field': field,
                                'value': value,
                                'severity': rule.get('severity', 50),
                                'count': len(window_events),
                                'events': window_events,
                                'timestamp': datetime.now().isoformat()
                            })
                else:
                    correlations.append({
                        'type': 'threshold',
                        'rule': rule.get('name'),
                        'field': field,
                        'value': value,
                        'severity': rule.get('severity', 50),
                        'count': len(value_events),
                        'events': value_events,
                        'timestamp': datetime.now().isoformat()
                    })
        
        return correlations
    
    def _detect_relationship(self, events: List[Dict], rule: Dict) -> List[Dict]:
        """Detect relationships between events"""
        correlations = []
        relationship_types = rule.get('relationship_types', ['same_source', 'same_target', 'same_user'])
        
        # Build relationship graph
        for event in events:
            source = event.get('src_ip')
            dest = event.get('dst_ip')
            user = event.get('user')
            
            if source and dest:
                self.relationship_graph.add_edge(source, dest, weight=self._calculate_edge_weight(event))
            
            if user and source:
                self.relationship_graph.add_edge(user, source, relationship='user_to_ip')
            
            if user and dest:
                self.relationship_graph.add_edge(user, dest, relationship='user_to_ip')
        
        # Detect relationship patterns
        for rel_type in relationship_types:
            if rel_type == 'same_source':
                grouped = defaultdict(list)
                for event in events:
                    src = event.get('src_ip')
                    if src:
                        grouped[src].append(event)
                
                for src, src_events in grouped.items():
                    if len(src_events) >= rule.get('min_events', 3):
                        correlations.append({
                            'type': 'relationship',
                            'subtype': 'same_source',
                            'rule': rule.get('name'),
                            'source': src,
                            'severity': rule.get('severity', 50),
                            'count': len(src_events),
                            'events': src_events,
                            'timestamp': datetime.now().isoformat()
                        })
            
            elif rel_type == 'same_target':
                grouped = defaultdict(list)
                for event in events:
                    dest = event.get('dst_ip')
                    if dest:
                        grouped[dest].append(event)
                
                for dest, dest_events in grouped.items():
                    if len(dest_events) >= rule.get('min_events', 3):
                        correlations.append({
                            'type': 'relationship',
                            'subtype': 'same_target',
                            'rule': rule.get('name'),
                            'target': dest,
                            'severity': rule.get('severity', 50),
                            'count': len(dest_events),
                            'events': dest_events,
                            'timestamp': datetime.now().isoformat()
                        })
            
            elif rel_type == 'same_user':
                grouped = defaultdict(list)
                for event in events:
                    user = event.get('user')
                    if user:
                        grouped[user].append(event)
                
                for user, user_events in grouped.items():
                    if len(user_events) >= rule.get('min_events', 3):
                        correlations.append({
                            'type': 'relationship',
                            'subtype': 'same_user',
                            'rule': rule.get('name'),
                            'user': user,
                            'severity': rule.get('severity', 50),
                            'count': len(user_events),
                            'events': user_events,
                            'timestamp': datetime.now().isoformat()
                        })
        
        return correlations
    
    async def _temporal_correlation(self, events: List[Dict]) -> List[Dict]:
        """Correlate events based on temporal patterns"""
        correlations = []
        
        # Extract temporal patterns
        time_patterns = self._extract_temporal_patterns(events)
        
        # Detect periodic patterns
        for pattern in time_patterns:
            if pattern.get('type') == 'periodic':
                correlations.append({
                    'type': 'temporal',
                    'subtype': 'periodic',
                    'pattern': pattern['pattern'],
                    'severity': 40,
                    'events': pattern['events'],
                    'timestamp': datetime.now().isoformat()
                })
            elif pattern.get('type') == 'sequential':
                correlations.append({
                    'type': 'temporal',
                    'subtype': 'sequential',
                    'pattern': pattern['pattern'],
                    'severity': 50,
                    'events': pattern['events'],
                    'timestamp': datetime.now().isoformat()
                })
        
        return correlations
    
    def _extract_temporal_patterns(self, events: List[Dict]) -> List[Dict]:
        """Extract temporal patterns from events"""
        patterns = []
        
        # Group events by source
        grouped = defaultdict(list)
        for event in events:
            key = event.get('src_ip')
            if key:
                grouped[key].append(event)
        
        for key, key_events in grouped.items():
            if len(key_events) < 3:
                continue
            
            # Sort by timestamp
            key_events.sort(key=lambda x: x.get('timestamp', ''))
            
            # Extract intervals
            intervals = []
            for i in range(len(key_events) - 1):
                t1 = datetime.fromisoformat(key_events[i].get('timestamp'))
                t2 = datetime.fromisoformat(key_events[i + 1].get('timestamp'))
                intervals.append((t2 - t1).total_seconds())
            
            # Check for periodic patterns
            if intervals:
                avg_interval = np.mean(intervals)
                std_interval = np.std(intervals)
                
                if std_interval / avg_interval < 0.2:  # 20% variance
                    patterns.append({
                        'type': 'periodic',
                        'key': key,
                        'pattern': f"Periodic with interval {avg_interval:.2f} seconds",
                        'events': key_events,
                        'confidence': 1 - (std_interval / avg_interval)
                    })
        
        return patterns
    
    async def _spatial_correlation(self, events: List[Dict]) -> List[Dict]:
        """Correlate events based on spatial proximity"""
        correlations = []
        
        # Group by geographical location
        grouped = defaultdict(list)
        for event in events:
            if 'src_geo' in event:
                geo = event['src_geo']
                key = f"{geo.get('country_code', '')}:{geo.get('city', '')}"
                grouped[key].append(event)
        
        for key, key_events in grouped.items():
            if len(key_events) >= 5:
                correlations.append({
                    'type': 'spatial',
                    'subtype': 'same_location',
                    'location': key,
                    'severity': 30,
                    'count': len(key_events),
                    'events': key_events,
                    'timestamp': datetime.now().isoformat()
                })
        
        return correlations
    
    async def _behavioral_correlation(self, events: List[Dict]) -> List[Dict]:
        """Correlate events based on behavioral patterns"""
        correlations = []
        
        # Group by behavioral signature
        grouped = defaultdict(list)
        for event in events:
            signature = self._generate_behavioral_signature(event)
            if signature:
                grouped[signature].append(event)
        
        for signature, signature_events in grouped.items():
            if len(signature_events) >= 3:
                correlations.append({
                    'type': 'behavioral',
                    'subtype': 'same_signature',
                    'signature': signature,
                    'severity': 35,
                    'count': len(signature_events),
                    'events': signature_events,
                    'timestamp': datetime.now().isoformat()
                })
        
        return correlations
    
    def _generate_behavioral_signature(self, event: Dict) -> str:
        """Generate behavioral signature for an event"""
        signature_parts = []
        
        # Include relevant fields
        for field in ['src_ip', 'dst_ip', 'protocol', 'user', 'event_type']:
            if field in event:
                signature_parts.append(f"{field}:{event[field]}")
        
        # Add timing pattern
        if 'timestamp' in event:
            dt = datetime.fromisoformat(event['timestamp'])
            hour = dt.hour
            if 9 <= hour < 17:  # Business hours
                signature_parts.append("business_hours")
            else:
                signature_parts.append("non_business_hours")
        
        return hashlib.md5('|'.join(signature_parts).encode()).hexdigest()
    
    async def _ml_correlation(self, events: List[Dict]) -> List[Dict]:
        """Use machine learning for correlation"""
        correlations = []
        
        if not self.correlation_model:
            return correlations
        
        try:
            # Extract features
            features = []
            for event in events:
                feat = self._extract_ml_features(event)
                features.append(feat)
            
            if features:
                X = np.array(features)
                X_scaled = self.anomaly_scaler.fit_transform(X)
                
                # Predict correlations
                predictions = self.correlation_model.predict(X_scaled)
                
                # Group by prediction
                grouped = defaultdict(list)
                for i, pred in enumerate(predictions):
                    grouped[pred].append(events[i])
                
                for pred, pred_events in grouped.items():
                    if len(pred_events) >= 3:
                        correlations.append({
                            'type': 'ml',
                            'subtype': 'cluster',
                            'cluster_id': pred,
                            'severity': 45,
                            'count': len(pred_events),
                            'events': pred_events,
                            'timestamp': datetime.now().isoformat()
                        })
        
        except Exception as e:
            self.logger.error(f"ML correlation error: {str(e)}")
        
        return correlations
    
    def _extract_ml_features(self, event: Dict) -> List[float]:
        """Extract features for ML model"""
        features = []
        
        # Numerical features
        features.append(float(event.get('size', 0)))
        features.append(float(event.get('risk_score', 0)))
        
        # Time features
        if 'timestamp' in event:
            dt = datetime.fromisoformat(event['timestamp'])
            features.append(float(dt.hour))
            features.append(float(dt.minute))
            features.append(float(dt.isocalendar()[2]))  # Day of week
        
        # Protocol features
        protocol = event.get('protocol')
        features.append(float(protocol == 'TCP'))
        features.append(float(protocol == 'UDP'))
        features.append(float(protocol == 'ICMP'))
        
        # Port features
        src_port = event.get('src_port', 0)
        dst_port = event.get('dst_port', 0)
        features.append(float(src_port))
        features.append(float(dst_port))
        features.append(float(src_port in [80, 443, 53]))
        features.append(float(dst_port in [80, 443, 53]))
        
        return features
    
    def _get_correlation_key(self, event: Dict, fields: List[str]) -> str:
        """Get correlation key for event"""
        if not fields:
            return ''
        
        key_parts = []
        for field in fields:
            if field in event:
                key_parts.append(str(event[field]))
        
        if key_parts:
            return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
        return ''
    
    def _matches_pattern(self, event: Dict, pattern: Dict) -> bool:
        """Check if event matches pattern"""
        for field, value in pattern.items():
            if field == 'timestamp':
                continue
            
            if field in event:
                if isinstance(value, dict):
                    # Check if value matches pattern
                    if value.get('type') == 'regex':
                        if not re.match(value['pattern'], str(event[field])):
                            return False
                    elif value.get('type') == 'range':
                        if not (value['min'] <= event[field] <= value['max']):
                            return False
                elif event[field] != value:
                    return False
        
        return True
    
    def _extract_features(self, event: Dict, fields: List[str]) -> List[float]:
        """Extract features from event"""
        features = []
        
        for field in fields:
            if field in event:
                value = event[field]
                if isinstance(value, (int, float)):
                    features.append(float(value))
                elif isinstance(value, str):
                    # Simple hash for string
                    features.append(float(hash(value) % 100) / 100.0)
                else:
                    features.append(0.0)
            else:
                features.append(0.0)
        
        return features
    
    def _calculate_edge_weight(self, event: Dict) -> float:
        """Calculate edge weight for graph"""
        weight = 1.0
        
        # Increase weight for high-risk events
        if event.get('risk_score', 0) > 70:
            weight *= 2.0
        
        # Increase weight for repeated events
        weight += event.get('frequency', 0) * 0.1
        
        # Adjust based on protocol
        if event.get('protocol') == 'TCP':
            weight *= 1.2
        elif event.get('protocol') == 'UDP':
            weight *= 0.8
        
        return min(weight, 10.0)
    
    async def get_correlation_graph(self) -> Dict:
        """Get correlation graph data"""
        graph_data = {
            'nodes': [],
            'edges': []
        }
        
        # Add nodes
        for node in self.relationship_graph.nodes():
            graph_data['nodes'].append({
                'id': node,
                'type': self._get_node_type(node)
            })
        
        # Add edges
        for edge in self.relationship_graph.edges(data=True):
            graph_data['edges'].append({
                'source': edge[0],
                'target': edge[1],
                'weight': edge[2].get('weight', 1.0)
            })
        
        return graph_data
    
    def _get_node_type(self, node: str) -> str:
        """Get node type for graph"""
        if self._is_ip(node):
            return 'ip'
        elif self._is_domain(node):
            return 'domain'
        elif '@' in node:
            return 'email'
        else:
            return 'unknown'
    
    def _is_ip(self, data: str) -> bool:
        """Check if string is IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(data)
            return True
        except:
            return False
    
    def _is_domain(self, data: str) -> bool:
        """Check if string is domain"""
        import re
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, data))