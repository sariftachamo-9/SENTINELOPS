#!/usr/bin/env python3
"""
Network Traffic Collector with Deep Packet Inspection
"""

import asyncio
import socket
import struct
import time
from typing import Dict, List, Any, Optional
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls import TLS
import dpkt
import geoip2.database
from elasticsearch import AsyncElasticsearch
import aiohttp
import json
from datetime import datetime
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from .base_collector import BaseCollector

class NetworkCollector(BaseCollector):
    """Advanced network traffic collector with deep packet inspection"""
    
    def __init__(self, config: Dict, logger):
        super().__init__(config, logger)
        
        self.interface = config.get('network', {}).get('interface', 'eth0')
        self.buffer_size = config.get('network', {}).get('buffer_size', 10000)
        self.sampling_rate = config.get('network', {}).get('sampling_rate', 1.0)
        
        # Session tracking
        self.sessions = {}
        self.packet_count = 0
        self.byte_count = 0
        
        # GeoIP database
        self.geoip_reader = geoip2.database.Reader(
            config.get('geoip', {}).get('database_path', 'GeoLite2-City.mmdb')
        )
        
        # ML models for anomaly detection
        self.feature_scaler = StandardScaler()
        self.anomaly_model = None
        self._load_models()
        
        # Threat intelligence cache
        self.threat_intel_cache = {}
        self.dns_cache = {}
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'bytes_processed': 0,
            'sessions_created': 0,
            'sessions_active': 0,
            'alerts_generated': 0
        }
    
    def _load_models(self):
        """Load ML models for anomaly detection"""
        try:
            import joblib
            self.anomaly_model = joblib.load('ml_models/network_anomaly_model.pkl')
            self.logger.info("Network anomaly detection model loaded")
        except Exception as e:
            self.logger.warning(f"Could not load ML model: {str(e)}")
    
    async def collect(self) -> List[Dict]:
        """Collect network events"""
        events = []
        
        try:
            # Collect packets using scapy
            packets = await self._capture_packets()
            
            for packet in packets:
                event = await self._process_packet(packet)
                if event:
                    events.append(event)
                    
                    # Check for high-risk events
                    if event.get('risk_score', 0) > 70:
                        await self._trigger_immediate_action(event)
            
            # Process session data
            session_events = await self._process_sessions()
            events.extend(session_events)
            
            # Update statistics
            self.stats['packets_processed'] += len(packets)
            self.stats['bytes_processed'] += sum(len(p) for p in packets)
            
        except Exception as e:
            self.logger.error(f"Network collection error: {str(e)}")
            raise
        
        return events
    
    async def _capture_packets(self) -> List:
        """Capture network packets with deep inspection"""
        packets = []
        
        try:
            # Use pcap for packet capture
            import pcap
            pcap_obj = pcap.pcap(self.interface)
            pcap_obj.setfilter(self._build_filter())
            
            # Capture packets with timeout
            packets_data = []
            start_time = time.time()
            
            while len(packets_data) < self.buffer_size:
                packet = pcap_obj.next()
                if packet:
                    packets_data.append(packet)
                if time.time() - start_time > self.config.get('capture_timeout', 5):
                    break
            
            # Process packets with scapy for deep inspection
            for timestamp, packet_data in packets_data:
                packet = self._decode_packet(packet_data)
                if packet and np.random.random() <= self.sampling_rate:
                    packets.append(packet)
                    
        except Exception as e:
            self.logger.error(f"Packet capture error: {str(e)}")
            # Fallback to scapy sniff
            packets = await self._fallback_capture()
        
        return packets
    
    def _build_filter(self) -> str:
        """Build BPF filter for packet capture"""
        filters = [
            "ip",
            "tcp",
            "udp",
            "icmp",
            "port 80",
            "port 443",
            "port 53",
            "port 22",
            "port 3389",
            "port 445"
        ]
        return " or ".join(filters)
    
    async def _fallback_capture(self) -> List:
        """Fallback packet capture using scapy"""
        packets = sniff(
            iface=self.interface,
            count=self.buffer_size,
            timeout=5,
            filter=self._build_filter()
        )
        return packets
    
    def _decode_packet(self, packet_data: bytes):
        """Decode raw packet data"""
        try:
            # Parse Ethernet header
            eth = dpkt.ethernet.Ethernet(packet_data)
            
            # Check for IP
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                packet = IP(bytes(ip))
                packet.time = time.time()
                return packet
            
        except Exception as e:
            self.logger.debug(f"Packet decode error: {str(e)}")
        
        return None
    
    async def _process_packet(self, packet) -> Optional[Dict]:
        """Process a single packet"""
        event = None
        
        try:
            # Extract basic information
            src_ip = packet[IP].src if IP in packet else None
            dst_ip = packet[IP].dst if IP in packet else None
            protocol = packet[IP].proto if IP in packet else None
            
            if not src_ip or not dst_ip:
                return None
            
            # Build base event
            event = {
                'timestamp': datetime.utcfromtimestamp(packet.time).isoformat(),
                'source': 'network',
                'event_type': 'network_traffic',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'size': len(packet),
                'raw_data': self._extract_raw_data(packet)
            }
            
            # Process transport layer
            if TCP in packet:
                await self._process_tcp_packet(packet, event)
            elif UDP in packet:
                await self._process_udp_packet(packet, event)
            elif ICMP in packet:
                await self._process_icmp_packet(packet, event)
            
            # Enrich with geoip
            event['src_geo'] = self._get_geoip(src_ip)
            event['dst_geo'] = self._get_geoip(dst_ip)
            
            # Check threat intelligence
            threat_intel = await self._check_threat_intel(src_ip, dst_ip)
            if threat_intel:
                event['threat_intel'] = threat_intel
            
            # Calculate risk score
            event['risk_score'] = self._calculate_risk_score(event)
            
            # Track sessions
            await self._track_session(event)
            
            # Update statistics
            self.packet_count += 1
            self.byte_count += len(packet)
            
        except Exception as e:
            self.logger.error(f"Packet processing error: {str(e)}")
            event = None
        
        return event
    
    async def _process_tcp_packet(self, packet, event: Dict):
        """Process TCP packet with deep inspection"""
        tcp = packet[TCP]
        event['src_port'] = tcp.sport
        event['dst_port'] = tcp.dport
        event['tcp_flags'] = self._get_tcp_flags(tcp)
        
        # Extract application layer data
        if tcp.dport == 80 or tcp.sport == 80:
            await self._process_http(packet, event)
        elif tcp.dport == 443 or tcp.sport == 443:
            await self._process_tls(packet, event)
        elif tcp.dport == 22 or tcp.sport == 22:
            await self._process_ssh(packet, event)
        elif tcp.dport == 445 or tcp.sport == 445:
            await self._process_smb(packet, event)
    
    async def _process_udp_packet(self, packet, event: Dict):
        """Process UDP packet"""
        udp = packet[UDP]
        event['src_port'] = udp.sport
        event['dst_port'] = udp.dport
        
        # Process DNS
        if udp.dport == 53 or udp.sport == 53:
            await self._process_dns(packet, event)
        
        # Process DHCP
        if udp.dport == 67 or udp.sport == 67 or udp.dport == 68 or udp.sport == 68:
            await self._process_dhcp(packet, event)
        
        # Process NTP
        if udp.dport == 123 or udp.sport == 123:
            await self._process_ntp(packet, event)
    
    async def _process_icmp_packet(self, packet, event: Dict):
        """Process ICMP packet"""
        icmp = packet[ICMP]
        event['icmp_type'] = icmp.type
        event['icmp_code'] = icmp.code
        
        # Detect ping sweeps and other ICMP scanning
        if icmp.type == 8:  # Echo request
            event['icmp_scan'] = await self._detect_icmp_scan(packet)
    
    async def _process_http(self, packet, event: Dict):
        """Process HTTP traffic with deep inspection"""
        try:
            http = HTTPRequest(packet[Raw].load)
            
            event['http'] = {
                'method': http.Method.decode() if http.Method else None,
                'host': http.Host.decode() if http.Host else None,
                'path': http.Path.decode() if http.Path else None,
                'user_agent': http.User_Agent.decode() if hasattr(http, 'User_Agent') else None,
                'headers': self._parse_http_headers(http)
            }
            
            # Detect attacks
            if self._detect_sql_injection(event['http']):
                event['attack_type'] = 'sql_injection'
                event['risk_score'] = max(event.get('risk_score', 0), 85)
            
            if self._detect_xss(event['http']):
                event['attack_type'] = 'xss'
                event['risk_score'] = max(event.get('risk_score', 0), 80)
            
            if self._detect_command_injection(event['http']):
                event['attack_type'] = 'command_injection'
                event['risk_score'] = max(event.get('risk_score', 0), 90)
            
        except Exception as e:
            self.logger.debug(f"HTTP processing error: {str(e)}")
    
    async def _process_tls(self, packet, event: Dict):
        """Process TLS/SSL traffic"""
        try:
            tls = TLS(packet[Raw].load)
            
            if tls.type == 22:  # Handshake
                handshake = tls.handshake
                if hasattr(handshake, 'client_hello'):
                    event['tls'] = {
                        'type': 'client_hello',
                        'version': self._get_tls_version(handshake),
                        'ciphers': handshake.cipher_suites,
                        'extensions': handshake.extensions
                    }
                    
                    # Check for weak ciphers
                    weak_ciphers = self._check_weak_ciphers(handshake.cipher_suites)
                    if weak_ciphers:
                        event['tls_weak_ciphers'] = weak_ciphers
                        event['risk_score'] = max(event.get('risk_score', 0), 30)
                    
                elif hasattr(handshake, 'server_hello'):
                    event['tls'] = {
                        'type': 'server_hello',
                        'version': self._get_tls_version(handshake),
                        'cipher': handshake.cipher_suite
                    }
        
        except Exception as e:
            self.logger.debug(f"TLS processing error: {str(e)}")
    
    async def _process_dns(self, packet, event: Dict):
        """Process DNS queries"""
        try:
            dns = DNS(packet[Raw].load)
            
            if DNSQR in dns:
                event['dns'] = {
                    'type': 'query',
                    'domain': dns[DNSQR].qname.decode() if dns[DNSQR] else None,
                    'type': dns[DNSQR].qtype
                }
                
                # Check for malicious domains
                if event['dns']['domain']:
                    is_malicious = await self._check_malicious_domain(event['dns']['domain'])
                    if is_malicious:
                        event['risk_score'] = max(event.get('risk_score', 0), 70)
                        event['threat_type'] = 'malicious_domain'
                        
                        # Add to threat intelligence cache
                        self.threat_intel_cache[event['dns']['domain']] = {
                            'malicious': True,
                            'timestamp': datetime.now().isoformat()
                        }
            
            if DNSRR in dns:
                event['dns']['response'] = {
                    'answers': [rr.rdata for rr in dns[DNSRR]]
                }
        
        except Exception as e:
            self.logger.debug(f"DNS processing error: {str(e)}")
    
    async def _check_malicious_domain(self, domain: str) -> bool:
        """Check domain against threat intelligence feeds"""
        # Check cache
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        # Check against multiple threat feeds
        is_malicious = False
        
        # Check against local threat intelligence
        if self._check_local_threat_intel(domain):
            is_malicious = True
        
        # Check against external APIs
        async with aiohttp.ClientSession() as session:
            # VirusTotal API
            if self.config.get('virustotal', {}).get('enabled'):
                if await self._check_virustotal(session, domain):
                    is_malicious = True
            
            # AlienVault OTX
            if self.config.get('alienvault', {}).get('enabled'):
                if await self._check_alienvault(session, domain):
                    is_malicious = True
            
            # Cisco Talos
            if self.config.get('talos', {}).get('enabled'):
                if await self._check_talos(session, domain):
                    is_malicious = True
        
        # Cache result
        self.dns_cache[domain] = is_malicious
        return is_malicious
    
    def _get_geoip(self, ip: str) -> Dict:
        """Get geoip information for IP"""
        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone
            }
        except:
            return {}
    
    def _detect_sql_injection(self, http_data: Dict) -> bool:
        """Detect SQL injection attacks in HTTP traffic"""
        patterns = [
            r"select.*from",
            r"union.*select",
            r"insert.*into",
            r"delete.*from",
            r"drop.*table",
            r"update.*set",
            r"exec.*xp_",
            r"1=1",
            r"or.*1=1",
            r"--",
            r";.*--"
        ]
        
        # Check URL and parameters
        import re
        url = http_data.get('path', '')
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check POST data
        if 'body' in http_data:
            for pattern in patterns:
                if re.search(pattern, http_data['body'], re.IGNORECASE):
                    return True
        
        return False
    
    def _detect_xss(self, http_data: Dict) -> bool:
        """Detect XSS attacks in HTTP traffic"""
        patterns = [
            r"<script.*>",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"onclick=",
            r"alert\(",
            r"document\.",
            r"window\.",
            r"eval\("
        ]
        
        import re
        url = http_data.get('path', '')
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def _detect_command_injection(self, http_data: Dict) -> bool:
        """Detect command injection attacks"""
        commands = [
            r";.*cat",
            r";.*ls",
            r";.*pwd",
            r";.*whoami",
            r";.*id",
            r";.*uname",
            r";.*echo",
            r";.*wget",
            r";.*curl",
            r";.*nc",
            r";.*netcat",
            r";.*bash",
            r";.*sh",
            r"|.*cat",
            r"|.*ls"
        ]
        
        import re
        url = http_data.get('path', '')
        for command in commands:
            if re.search(command, url, re.IGNORECASE):
                return True
        
        return False
    
    async def _track_session(self, event: Dict):
        """Track network sessions"""
        key = f"{event.get('src_ip')}:{event.get('src_port')}-{event.get('dst_ip')}:{event.get('dst_port')}"
        
        if key not in self.sessions:
            self.sessions[key] = {
                'start_time': event['timestamp'],
                'packets_count': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'protocol': event.get('protocol')
            }
            self.stats['sessions_created'] += 1
        
        # Update session
        session = self.sessions[key]
        session['packets_count'] += 1
        session['bytes_sent'] += event.get('size', 0)
        
        # Check for long-running sessions
        session_duration = (datetime.now() - datetime.fromisoformat(session['start_time'])).total_seconds()
        if session_duration > 3600:  # 1 hour
            event['long_session'] = True
            event['risk_score'] = max(event.get('risk_score', 0), 20)
        
        self.stats['sessions_active'] = len(self.sessions)
    
    async def _process_sessions(self) -> List[Dict]:
        """Process active sessions and detect patterns"""
        events = []
        
        for session_key, session_data in self.sessions.items():
            # Check for suspicious session patterns
            if session_data['packets_count'] > 10000:
                events.append({
                    'source': 'network',
                    'event_type': 'high_volume_session',
                    'session_key': session_key,
                    'packets_count': session_data['packets_count'],
                    'bytes_sent': session_data['bytes_sent'],
                    'risk_score': 60
                })
            
            # Check for data exfiltration
            if session_data['bytes_sent'] > 1000000000:  # 1GB
                events.append({
                    'source': 'network',
                    'event_type': 'potential_data_exfiltration',
                    'session_key': session_key,
                    'bytes_sent': session_data['bytes_sent'],
                    'risk_score': 80
                })
        
        # Clear old sessions
        current_time = datetime.now()
        for key in list(self.sessions.keys()):
            session_time = datetime.fromisoformat(self.sessions[key]['start_time'])
            if (current_time - session_time).total_seconds() > 86400:  # 24 hours
                del self.sessions[key]
        
        return events
    
    def _calculate_risk_score(self, event: Dict) -> int:
        """Calculate risk score for network event"""
        score = 0
        
        # Source IP reputation
        if event.get('src_ip'):
            reputation = self._get_ip_reputation(event['src_ip'])
            score += reputation * 10
        
        # Destination IP reputation
        if event.get('dst_ip'):
            reputation = self._get_ip_reputation(event['dst_ip'])
            score += reputation * 10
        
        # Suspicious ports
        suspicious_ports = [23, 21, 25, 135, 137, 139, 445, 1433, 3306, 3389]
        if event.get('dst_port') in suspicious_ports:
            score += 20
        if event.get('src_port') in suspicious_ports:
            score += 10
        
        # Attack detection
        if event.get('attack_type'):
            score += 30
        
        # Threat intelligence
        if event.get('threat_intel'):
            score += 25
        
        # Anomaly detection
        if event.get('is_anomaly'):
            score += 20
        
        # Data size
        if event.get('size', 0) > 1000000:
            score += 15
        
        # GeoIP high-risk countries
        high_risk_countries = ['RU', 'CN', 'IR', 'KP', 'SY']
        if event.get('src_geo', {}).get('country_code') in high_risk_countries:
            score += 15
        if event.get('dst_geo', {}).get('country_code') in high_risk_countries:
            score += 10
        
        return min(score, 100)
    
    def _get_ip_reputation(self, ip: str) -> float:
        """Get IP reputation score"""
        # Check against threat feeds
        if ip in self.threat_intel_cache:
            return 1.0
        
        # Check against local blacklists
        if self._check_local_blacklist(ip):
            return 0.8
        
        return 0.0
    
    def _check_local_blacklist(self, ip: str) -> bool:
        """Check IP against local blacklist"""
        # Implementation using local blacklist database
        return False
    
    def _get_tcp_flags(self, tcp) -> Dict:
        """Get TCP flags"""
        return {
            'syn': tcp.SYN,
            'ack': tcp.ACK,
            'fin': tcp.FIN,
            'rst': tcp.RST,
            'psh': tcp.PSH,
            'urg': tcp.URG
        }
    
    def _get_tls_version(self, handshake) -> str:
        """Get TLS version"""
        versions = {
            0x0303: "TLSv1.2",
            0x0304: "TLSv1.3",
            0x0302: "TLSv1.1",
            0x0301: "TLSv1.0",
            0x0300: "SSLv3"
        }
        return versions.get(handshake.version, "Unknown")
    
    def _check_weak_ciphers(self, ciphers: List) -> List:
        """Check for weak TLS ciphers"""
        weak_ciphers = [
            0x0005,  # RC4-SHA
            0x0004,  # RC4-MD5
            0x000A,  # DES-CBC3-SHA
            0x0016,  # DHE-DSS-AES128-SHA
            0x0033,  # DHE-RSA-AES128-SHA
            0x0035,  # DHE-RSA-AES256-SHA
        ]
        
        weak_found = []
        for cipher in ciphers:
            if cipher in weak_ciphers:
                weak_found.append(hex(cipher))
        
        return weak_found
    
    def _extract_raw_data(self, packet) -> Dict:
        """Extract raw packet data"""
        raw_data = {
            'size': len(packet),
            'summary': packet.summary()
        }
        
        if Raw in packet:
            try:
                raw_data['payload'] = packet[Raw].load[:1000].hex()  # First 1000 bytes
            except:
                pass
        
        return raw_data
    
    def _parse_http_headers(self, http) -> Dict:
        """Parse HTTP headers"""
        headers = {}
        for key, value in http.fields.items():
            if isinstance(key, bytes):
                key = key.decode('utf-8', errors='ignore')
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
            headers[key] = value
        return headers
    
    async def _trigger_immediate_action(self, event: Dict):
        """Trigger immediate action for high-risk events"""
        # Block IP in firewall
        if event.get('src_ip'):
            await self._block_ip(event['src_ip'], event.get('risk_score'))
        
        # Send high-priority alert
        await self._send_high_priority_alert(event)
    
    async def _block_ip(self, ip: str, risk_score: int):
        """Block IP in firewall"""
        # Implementation for firewall integration
        pass
    
    async def _send_high_priority_alert(self, event: Dict):
        """Send high-priority alert"""
        # Implementation for alerting
        pass

    async def _check_virustotal(self, session: aiohttp.ClientSession, domain: str) -> bool:
        """Check domain against VirusTotal"""
        # Implementation
        pass
    
    async def _check_alienvault(self, session: aiohttp.ClientSession, domain: str) -> bool:
        """Check domain against AlienVault OTX"""
        # Implementation
        pass
    
    async def _check_talos(self, session: aiohttp.ClientSession, domain: str) -> bool:
        """Check domain against Cisco Talos"""
        # Implementation
        pass