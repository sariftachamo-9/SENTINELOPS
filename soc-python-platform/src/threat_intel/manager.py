#!/usr/bin/env python3
"""
Advanced Threat Intelligence Manager
"""

import asyncio
import aiohttp
import json
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
import redis
import sqlite3
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import pickle
import yaml
import logging
import ipaddress
import dns.resolver
from urllib.parse import urlparse

class ThreatIntelManager:
    """Advanced Threat Intelligence Management System"""
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        
        # Initialize Redis cache
        self.redis = redis.Redis(
            host=config.get('redis', {}).get('host', 'localhost'),
            port=config.get('redis', {}).get('port', 6379),
            decode_responses=True
        )
        
        # Initialize local SQLite database
        self.db = sqlite3.connect('threat_intel.db')
        self._init_database()
        
        # Initialize ML models
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000)
        self.classifier = RandomForestClassifier(n_estimators=100)
        self._load_ml_models()
        
        # Threat feeds
        self.threat_feeds = config.get('threat_feeds', [])
        self.indicators = {}
        self.intelligence_sources = {}
        
        # Statistics
        self.stats = {
            'indicators_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'feed_updates': 0,
            'last_update': datetime.now().isoformat()
        }
        
        # Initialize threat indicators
        self._load_initial_indicators()
    
    def _init_database(self):
        """Initialize SQLite database for threat intelligence"""
        cursor = self.db.cursor()
        
        # Create indicators table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                type TEXT NOT NULL,
                severity INTEGER,
                confidence INTEGER,
                source TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                metadata TEXT,
                UNIQUE(indicator, type)
            )
        ''')
        
        # Create threat actors table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_actors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                aliases TEXT,
                motivation TEXT,
                sophistication INTEGER,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                metadata TEXT,
                UNIQUE(name)
            )
        ''')
        
        # Create campaigns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                threat_actor_id INTEGER,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                techniques TEXT,
                objectives TEXT,
                metadata TEXT,
                FOREIGN KEY(threat_actor_id) REFERENCES threat_actors(id)
            )
        ''')
        
        # Create relationships table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indicator_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id1 INTEGER,
                indicator_id2 INTEGER,
                relationship_type TEXT,
                confidence INTEGER,
                metadata TEXT,
                FOREIGN KEY(indicator_id1) REFERENCES indicators(id),
                FOREIGN KEY(indicator_id2) REFERENCES indicators(id)
            )
        ''')
        
        self.db.commit()
    
    def _load_initial_indicators(self):
        """Load initial threat indicators from local files"""
        try:
            with open('config/threat_intel/initial_indicators.json', 'r') as f:
                indicators = json.load(f)
                for indicator in indicators:
                    self.add_indicator(indicator)
        except Exception as e:
            self.logger.warning(f"Could not load initial indicators: {str(e)}")
    
    def _load_ml_models(self):
        """Load machine learning models"""
        try:
            with open('ml_models/threat_classifier.pkl', 'rb') as f:
                self.classifier = pickle.load(f)
            
            with open('ml_models/tfidf_vectorizer.pkl', 'rb') as f:
                self.tfidf_vectorizer = pickle.load(f)
                
            self.logger.info("Threat intelligence ML models loaded")
        except Exception as e:
            self.logger.warning(f"Could not load ML models: {str(e)}")
    
    def add_indicator(self, indicator_data: Dict) -> bool:
        """Add a new threat indicator"""
        try:
            cursor = self.db.cursor()
            
            # Parse indicator data
            indicator = indicator_data.get('indicator')
            indicator_type = indicator_data.get('type')
            severity = indicator_data.get('severity', 50)
            confidence = indicator_data.get('confidence', 70)
            source = indicator_data.get('source', 'manual')
            metadata = json.dumps(indicator_data.get('metadata', {}))
            
            # Validate indicator
            if not indicator or not indicator_type:
                self.logger.warning("Invalid indicator data")
                return False
            
            # Check if indicator exists
            cursor.execute(
                "SELECT id FROM indicators WHERE indicator = ? AND type = ?",
                (indicator, indicator_type)
            )
            existing = cursor.fetchone()
            
            if existing:
                # Update existing indicator
                cursor.execute('''
                    UPDATE indicators 
                    SET severity = ?, confidence = ?, last_seen = CURRENT_TIMESTAMP, metadata = ?
                    WHERE id = ?
                ''', (severity, confidence, metadata, existing[0]))
            else:
                # Insert new indicator
                cursor.execute('''
                    INSERT INTO indicators (indicator, type, severity, confidence, source, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (indicator, indicator_type, severity, confidence, source, metadata))
            
            # Add to cache
            cache_key = f"indicator:{indicator_type}:{indicator}"
            self.redis.setex(
                cache_key,
                3600,  # 1 hour TTL
                json.dumps({
                    'indicator': indicator,
                    'type': indicator_type,
                    'severity': severity,
                    'confidence': confidence,
                    'source': source,
                    'metadata': metadata
                })
            )
            
            self.db.commit()
            self.stats['indicators_processed'] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding indicator: {str(e)}")
            return False
    
    async def check_indicator(self, data: str, types: List[str] = None) -> Dict:
        """Check if data is a known threat indicator"""
        result = {
            'is_threat': False,
            'indicators': [],
            'confidence': 0,
            'severity': 0
        }
        
        if not types:
            types = ['ip', 'domain', 'url', 'hash', 'email']
        
        for indicator_type in types:
            indicator = None
            
            # Parse based on type
            if indicator_type == 'ip' and self._is_ip(data):
                indicator = data
            elif indicator_type == 'domain' and self._is_domain(data):
                indicator = data
            elif indicator_type == 'url' and self._is_url(data):
                indicator = data
            elif indicator_type == 'hash' and self._is_hash(data):
                indicator = data
            elif indicator_type == 'email' and self._is_email(data):
                indicator = data
            
            if indicator:
                # Check in database
                cursor = self.db.cursor()
                cursor.execute(
                    "SELECT * FROM indicators WHERE indicator = ? AND type = ?",
                    (indicator, indicator_type)
                )
                db_result = cursor.fetchone()
                
                if db_result:
                    result['is_threat'] = True
                    result['indicators'].append({
                        'type': indicator_type,
                        'value': indicator,
                        'severity': db_result[3],
                        'confidence': db_result[4]
                    })
                    result['confidence'] = max(result['confidence'], db_result[4])
                    result['severity'] = max(result['severity'], db_result[3])
        
        return result
    
    async def enrich_with_threat_intel(self, event: Dict) -> Dict:
        """Enrich an event with threat intelligence"""
        enriched = event.copy()
        
        # Check various fields
        fields_to_check = ['src_ip', 'dst_ip', 'domain', 'url', 'email']
        
        for field in fields_to_check:
            if field in event and event[field]:
                result = await self.check_indicator(event[field])
                if result['is_threat']:
                    enriched[f'{field}_threat_intel'] = result
                    enriched['threat_detected'] = True
                    enriched['threat_confidence'] = result['confidence']
                    enriched['threat_severity'] = result['severity']
                    
                    # Add to risk score
                    if 'risk_score' in enriched:
                        enriched['risk_score'] += result['severity'] / 10
        
        return enriched
    
    async def get_threat_actors(self, indicator: str) -> List[Dict]:
        """Get threat actors associated with an indicator"""
        actors = []
        
        cursor = self.db.cursor()
        cursor.execute('''
            SELECT ta.* FROM threat_actors ta
            JOIN campaigns c ON c.threat_actor_id = ta.id
            JOIN indicator_relationships ir ON ir.indicator_id1 = c.id
            JOIN indicators i ON i.id = ir.indicator_id2
            WHERE i.indicator = ?
        ''', (indicator,))
        
        for row in cursor.fetchall():
            actors.append({
                'id': row[0],
                'name': row[1],
                'aliases': row[2],
                'motivation': row[3],
                'sophistication': row[4]
            })
        
        return actors
    
    async def get_similar_indicators(self, indicator: str, limit: int = 10) -> List[Dict]:
        """Find similar threat indicators"""
        similar = []
        
        cursor = self.db.cursor()
        # Using simple LIKE for similarity (in production, use proper similarity)
        cursor.execute('''
            SELECT * FROM indicators 
            WHERE indicator LIKE ? OR indicator LIKE ?
            LIMIT ?
        ''', (f'%{indicator[:10]}%', f'%{indicator[-10:]}%', limit))
        
        for row in cursor.fetchall():
            similar.append({
                'indicator': row[1],
                'type': row[2],
                'severity': row[3],
                'confidence': row[4]
            })
        
        return similar
    
    async def update_from_feeds(self):
        """Update threat intelligence from external feeds"""
        self.logger.info("Updating threat intelligence from feeds...")
        
        for feed in self.threat_feeds:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(feed['url']) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            for indicator in data.get('indicators', []):
                                indicator_data = {
                                    'indicator': indicator.get('value'),
                                    'type': indicator.get('type'),
                                    'severity': indicator.get('severity', 50),
                                    'confidence': indicator.get('confidence', 70),
                                    'source': feed['name'],
                                    'metadata': indicator.get('metadata', {})
                                }
                                self.add_indicator(indicator_data)
                            
                            self.stats['feed_updates'] += 1
                            self.logger.info(f"Updated from feed: {feed['name']}")
            except Exception as e:
                self.logger.error(f"Error updating from feed {feed['name']}: {str(e)}")
        
        self.stats['last_update'] = datetime.now().isoformat()
    
    def _is_ip(self, data: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(data)
            return True
        except:
            return False
    
    def _is_domain(self, data: str) -> bool:
        """Check if string is a valid domain"""
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, data))
    
    def _is_url(self, data: str) -> bool:
        """Check if string is a valid URL"""
        try:
            result = urlparse(data)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_hash(self, data: str) -> bool:
        """Check if string is a valid hash"""
        hash_patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$'
        }
        return any(re.match(pattern, data) for pattern in hash_patterns.values())
    
    def _is_email(self, data: str) -> bool:
        """Check if string is a valid email"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, data))
    
    async def classify_threat(self, data: Dict) -> Dict:
        """Classify threat using machine learning"""
        # Extract features
        features = self._extract_features(data)
        
        # Vectorize
        vectorized = self.tfidf_vectorizer.transform([features])
        
        # Predict
        prediction = self.classifier.predict(vectorized)
        probability = self.classifier.predict_proba(vectorized)
        
        return {
            'threat_class': prediction[0],
            'confidence': max(probability[0]),
            'threat_level': self._calculate_threat_level(probability[0])
        }
    
    def _extract_features(self, data: Dict) -> str:
        """Extract features for ML classification"""
        features = []
        
        # Extract relevant fields
        if 'src_ip' in data:
            features.append(data['src_ip'])
        if 'dst_ip' in data:
            features.append(data['dst_ip'])
        if 'domain' in data:
            features.append(data['domain'])
        if 'url' in data:
            features.append(data['url'])
        if 'user_agent' in data:
            features.append(data['user_agent'])
        
        return ' '.join(features)
    
    def _calculate_threat_level(self, probabilities: List) -> str:
        """Calculate threat level from probabilities"""
        max_prob = max(probabilities)
        
        if max_prob > 0.9:
            return 'critical'
        elif max_prob > 0.7:
            return 'high'
        elif max_prob > 0.5:
            return 'medium'
        elif max_prob > 0.3:
            return 'low'
        else:
            return 'informational'
    
    async def correlate_intelligence(self) -> List[Dict]:
        """Correlate threat intelligence data"""
        correlations = []
        
        cursor = self.db.cursor()
        
        # Find indicators with high correlation
        cursor.execute('''
            SELECT i1.indicator, i1.type, i2.indicator, i2.type, COUNT(*) as freq
            FROM indicators i1
            JOIN indicator_relationships ir ON ir.indicator_id1 = i1.id
            JOIN indicators i2 ON i2.id = ir.indicator_id2
            WHERE ir.confidence > 70
            GROUP BY i1.indicator, i1.type, i2.indicator, i2.type
            ORDER BY freq DESC
            LIMIT 20
        ''')
        
        for row in cursor.fetchall():
            correlations.append({
                'indicator1': row[0],
                'type1': row[1],
                'indicator2': row[2],
                'type2': row[3],
                'frequency': row[4]
            })
        
        return correlations
    
    async def get_intelligence_report(self, start_date: str, end_date: str) -> Dict:
        """Generate threat intelligence report"""
        cursor = self.db.cursor()
        
        # Get indicator statistics
        cursor.execute('''
            SELECT type, COUNT(*) as count, AVG(severity) as avg_severity
            FROM indicators
            WHERE first_seen BETWEEN ? AND ?
            GROUP BY type
        ''', (start_date, end_date))
        
        indicator_stats = cursor.fetchall()
        
        # Get threat actor statistics
        cursor.execute('''
            SELECT name, COUNT(*) as indicator_count
            FROM threat_actors ta
            JOIN campaigns c ON c.threat_actor_id = ta.id
            JOIN indicator_relationships ir ON ir.indicator_id1 = c.id
            WHERE c.start_date BETWEEN ? AND ?
            GROUP BY ta.id
        ''', (start_date, end_date))
        
        actor_stats = cursor.fetchall()
        
        return {
            'period': {
                'start': start_date,
                'end': end_date
            },
            'indicator_stats': [
                {
                    'type': row[0],
                    'count': row[1],
                    'avg_severity': row[2]
                } for row in indicator_stats
            ],
            'threat_actors': [
                {
                    'name': row[0],
                    'indicator_count': row[1]
                } for row in actor_stats
            ],
            'total_indicators': self.stats['indicators_processed'],
            'threats_detected': self.stats['threats_detected'],
            'false_positive_rate': self.stats['false_positives'] / max(self.stats['threats_detected'], 1)
        }
    
    def close(self):
        """Close connections"""
        self.db.close()