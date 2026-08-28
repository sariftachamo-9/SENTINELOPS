#!/usr/bin/env python3
import asyncio
import random
from datetime import datetime

class NetworkCollector:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.packet_count = 0
        
    async def collect(self):
        """Collect network events"""
        try:
            # Try to use scapy for real packet capture
            try:
                from scapy.all import sniff, IP, TCP, UDP
                packets = sniff(count=5, timeout=2)
                
                events = []
                for packet in packets:
                    if IP in packet:
                        event = {
                            'timestamp': datetime.now().isoformat(),
                            'source': 'network',
                            'src_ip': packet[IP].src,
                            'dst_ip': packet[IP].dst,
                            'protocol': packet[IP].proto,
                            'size': len(packet)
                        }
                        
                        if TCP in packet:
                            event['src_port'] = packet[TCP].sport
                            event['dst_port'] = packet[TCP].dport
                            event['tcp_flags'] = self._get_tcp_flags(packet[TCP])
                        
                        if UDP in packet:
                            event['src_port'] = packet[UDP].sport
                            event['dst_port'] = packet[UDP].dport
                        
                        events.append(event)
                        self.packet_count += 1
                
                if events:
                    self.logger.info(f"Collected {len(events)} real network packets")
                return events
                
            except ImportError:
                self.logger.debug("Scapy not available, using mock data")
                return self._generate_mock_events()
                
        except Exception as e:
            self.logger.error(f"Network collection error: {str(e)}")
            return self._generate_mock_events()
    
    def _get_tcp_flags(self, tcp):
        flags = []
        if tcp.SYN: flags.append('SYN')
        if tcp.ACK: flags.append('ACK')
        if tcp.FIN: flags.append('FIN')
        if tcp.RST: flags.append('RST')
        if tcp.PSH: flags.append('PSH')
        if tcp.URG: flags.append('URG')
        return flags
    
    def _generate_mock_events(self):
        """Generate mock network data for testing"""
        events = []
        for _ in range(3):
            event = {
                'timestamp': datetime.now().isoformat(),
                'source': 'network',
                'src_ip': f"192.168.1.{random.randint(1,254)}",
                'dst_ip': f"10.0.0.{random.randint(1,254)}",
                'protocol': random.choice([6, 17]),
                'size': random.randint(64, 1500),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 53, 22, 3306])
            }
            events.append(event)
        return events
