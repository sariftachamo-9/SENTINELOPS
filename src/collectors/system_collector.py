#!/usr/bin/env python3
import psutil
from datetime import datetime

class SystemCollector:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        
    async def collect(self):
        """Collect system metrics"""
        try:
            events = []
            
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.5)
            
            # Memory
            memory = psutil.virtual_memory()
            
            # Disk
            disk = psutil.disk_usage('/')
            
            # Network
            net_io = psutil.net_io_counters()
            
            event = {
                'timestamp': datetime.now().isoformat(),
                'source': 'system',
                'type': 'metrics',
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_percent': disk.percent,
                'network_bytes_sent': net_io.bytes_sent,
                'network_bytes_recv': net_io.bytes_recv
            }
            
            # Check for alerts
            if cpu_percent > 80:
                event['alert'] = f'High CPU usage: {cpu_percent}%'
                event['severity'] = 'warning'
            
            if memory.percent > 85:
                event['alert'] = f'High memory usage: {memory.percent}%'
                event['severity'] = 'warning'
            
            events.append(event)
            return events
            
        except Exception as e:
            self.logger.error(f"System collection error: {str(e)}")
            return []
