#!/usr/bin/env python3
import asyncio
import sys
import os
import json
import logging
import random
from datetime import datetime

logger = logging.getLogger('SOCPlatform')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

class SOCPlatform:
    def __init__(self):
        self.is_running = True
        self.events_processed = 0
        self.alerts_generated = 0
        self.incidents_created = 0
        self.collected_data = []
        
    async def start(self):
        logger.info("=" * 60)
        logger.info("🛡️ SOC Platform Starting...")
        logger.info(f"Time: {datetime.now().isoformat()}")
        logger.info("=" * 60)
        
        counter = 0
        while self.is_running:
            counter += 1
            
            # Simulate data collection
            await self._collect_data()
            
            # Log status every 5 seconds
            if counter % 5 == 0:
                logger.info(f"Running... {counter}s | Events: {self.events_processed} | Alerts: {self.alerts_generated} | Incidents: {self.incidents_created}")
            
            # Generate test alert every 20 seconds
            if counter % 20 == 0:
                self.alerts_generated += 1
                self.incidents_created += 1
                alert_msg = f"⚠️ Test Alert #{self.alerts_generated} - Suspicious activity detected!"
                incident_msg = f"🚨 Incident #{self.incidents_created} created from Alert #{self.alerts_generated}"
                logger.warning(alert_msg)
                logger.critical(incident_msg)
                
                # Store alert data for API
                self.collected_data.append({
                    'type': 'alert',
                    'timestamp': datetime.now().isoformat(),
                    'message': alert_msg,
                    'alert_id': f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    'severity': 'high'
                })
            
            await asyncio.sleep(1)
    
    async def _collect_data(self):
        """Simulate data collection"""
        self.events_processed += 1
        
        # Randomly generate events
        if random.random() < 0.3:  # 30% chance
            event = {
                'timestamp': datetime.now().isoformat(),
                'source': 'network',
                'src_ip': f"192.168.1.{random.randint(1,254)}",
                'dst_ip': f"10.0.0.{random.randint(1,254)}",
                'size': random.randint(64, 1500)
            }
            self.collected_data.append(event)
    
    async def shutdown(self):
        logger.info("Shutting down SOC Platform...")
        self.is_running = False
        logger.info(f"Final stats - Events: {self.events_processed}, Alerts: {self.alerts_generated}, Incidents: {self.incidents_created}")
        logger.info("Goodbye!")

async def main():
    platform = SOCPlatform()
    try:
        await platform.start()
    except KeyboardInterrupt:
        await platform.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
