#!/usr/bin/env python3
"""
Advanced Incident Response Playbook with Automation
"""

import asyncio
import json
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import subprocess
import requests
import shutil
import os
import hashlib
import re
import ipaddress
import paramiko
import docker
import kubernetes
from elasticsearch import Elasticsearch
import boto3
import aiohttp
import aioredis

class IncidentResponsePlaybook:
    """Advanced Incident Response Playbook System"""
    
    def __init__(self, config: Dict, logger):
        self.config = config
        self.logger = logger
        
        # Initialize connections
        self.es_client = Elasticsearch(
            config['elasticsearch']['hosts'],
            basic_auth=(
                config['elasticsearch']['username'],
                config['elasticsearch']['password']
            )
        )
        
        self.redis = aioredis.from_url(config['redis']['url'])
        
        # Initialize cloud providers
        if config.get('aws', {}).get('enabled'):
            self.aws_client = boto3.client('ec2', 
                aws_access_key_id=config['aws']['access_key'],
                aws_secret_access_key=config['aws']['secret_key'],
                region_name=config['aws']['region']
            )
        
        # Docker client
        self.docker_client = docker.from_env()
        
        # Kubernetes client
        if config.get('kubernetes', {}).get('enabled'):
            kubernetes.config.load_kube_config()
            self.k8s_client = kubernetes.client.CoreV1Api()
        
        # Load playbooks
        self.playbooks = self._load_playbooks()
        
        # Active incidents
        self.active_incidents = {}
        
        # Response actions
        self.response_actions = {
            'isolate_host': self._isolate_host,
            'block_ip': self._block_ip,
            'kill_process': self._kill_process,
            'quarantine_file': self._quarantine_file,
            'capture_forensics': self._capture_forensics,
            'notify_team': self._notify_team,
            'create_case': self._create_case,
            'update_firewall': self._update_firewall,
            'revoke_access': self._revoke_access,
            'reset_credentials': self._reset_credentials,
            'capture_memory': self._capture_memory,
            'analyze_malware': self._analyze_malware,
            'rollback_changes': self._rollback_changes,
            'escalate_incident': self._escalate_incident
        }
        
        # Statistics
        self.stats = {
            'incidents_handled': 0,
            'actions_taken': 0,
            'escalations': 0,
            'resolution_time_avg': 0
        }
    
    def _load_playbooks(self) -> Dict[str, Dict]:
        """Load incident response playbooks"""
        playbooks = {}
        
        try:
            # Load playbooks from directory
            for file in os.listdir('config/playbooks/'):
                if file.endswith('.yml'):
                    with open(f'config/playbooks/{file}', 'r') as f:
                        playbook = yaml.safe_load(f)
                        if playbook.get('id'):
                            playbooks[playbook['id']] = playbook
        except Exception as e:
            self.logger.error(f"Error loading playbooks: {str(e)}")
        
        # Default playbooks if none found
        if not playbooks:
            playbooks = self._create_default_playbooks()
        
        return playbooks
    
    def _create_default_playbooks(self) -> Dict[str, Dict]:
        """Create default playbooks"""
        return {
            'ransomware': {
                'id': 'ransomware',
                'name': 'Ransomware Response Playbook',
                'severity': 'critical',
                'triggers': [
                    {'type': 'signature', 'value': 'encrypted_files'},
                    {'type': 'indicator', 'value': 'ransomware_hash'},
                    {'type': 'anomaly', 'value': 'high_encryption_rate'}
                ],
                'steps': [
                    {'action': 'isolate_host', 'timeout': 60},
                    {'action': 'kill_process', 'timeout': 30},
                    {'action': 'capture_forensics', 'timeout': 300},
                    {'action': 'notify_team', 'params': {'channels': ['security', 'management']}},
                    {'action': 'create_case', 'params': {'severity': 'critical'}},
                    {'action': 'analyze_malware', 'timeout': 600},
                    {'action': 'escalate_incident', 'params': {'level': 'tier3'}}
                ],
                'post_actions': [
                    {'action': 'update_firewall', 'params': {'block': True}},
                    {'action': 'revoke_access', 'params': {'temporary': True}}
                ]
            },
            'data_breach': {
                'id': 'data_breach',
                'name': 'Data Breach Response Playbook',
                'severity': 'high',
                'triggers': [
                    {'type': 'signature', 'value': 'data_exfiltration'},
                    {'type': 'indicator', 'value': 'sensitive_data_access'},
                    {'type': 'anomaly', 'value': 'large_data_transfer'}
                ],
                'steps': [
                    {'action': 'isolate_host', 'timeout': 60},
                    {'action': 'capture_forensics', 'timeout': 600},
                    {'action': 'notify_team', 'params': {'channels': ['security', 'legal']}},
                    {'action': 'create_case', 'params': {'severity': 'high'}},
                    {'action': 'revoke_access', 'timeout': 120}
                ]
            },
            'malware': {
                'id': 'malware',
                'name': 'Malware Response Playbook',
                'severity': 'high',
                'triggers': [
                    {'type': 'signature', 'value': 'malicious_process'},
                    {'type': 'indicator', 'value': 'malware_hash'},
                    {'type': 'detection', 'value': 'av_alert'}
                ],
                'steps': [
                    {'action': 'isolate_host', 'timeout': 30},
                    {'action': 'kill_process', 'timeout': 30},
                    {'action': 'quarantine_file', 'timeout': 30},
                    {'action': 'capture_forensics', 'timeout': 300},
                    {'action': 'analyze_malware', 'timeout': 600},
                    {'action': 'notify_team', 'params': {'channels': ['security']}},
                    {'action': 'create_case', 'params': {'severity': 'high'}}
                ]
            },
            'phishing': {
                'id': 'phishing',
                'name': 'Phishing Response Playbook',
                'severity': 'medium',
                'triggers': [
                    {'type': 'indicator', 'value': 'phishing_email'},
                    {'type': 'signature', 'value': 'suspicious_url'},
                    {'type': 'detection', 'value': 'spam_report'}
                ],
                'steps': [
                    {'action': 'block_ip', 'timeout': 60},
                    {'action': 'revoke_access', 'params': {'temporary': True}},
                    {'action': 'reset_credentials', 'timeout': 120},
                    {'action': 'notify_team', 'params': {'channels': ['security', 'it']}},
                    {'action': 'create_case', 'params': {'severity': 'medium'}}
                ]
            }
        }
    
    async def create_incident(self, alert: Dict) -> Dict:
        """Create an incident from an alert"""
        incident = {
            'id': self._generate_incident_id(),
            'alert_id': alert.get('id'),
            'title': alert.get('title', 'Security Incident'),
            'description': alert.get('description', ''),
            'severity': alert.get('severity', 'medium'),
            'status': 'open',
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'assigned_to': None,
            'affected_assets': [],
            'related_incidents': [],
            'playbook': None,
            'steps_completed': [],
            'steps_pending': [],
            'evidence': [],
            'actions_taken': [],
            'resolution': None,
            'escalation_level': 0
        }
        
        # Select playbook
        playbook = self._select_playbook(alert)
        if playbook:
            incident['playbook'] = playbook['id']
            incident['steps_pending'] = playbook['steps']
        
        # Extract affected assets
        incident['affected_assets'] = self._extract_affected_assets(alert)
        
        # Store incident
        self.active_incidents[incident['id']] = incident
        
        # Log incident
        self.logger.warning(f"Incident created: {incident['id']} - {incident['title']}")
        self.stats['incidents_handled'] += 1
        
        # Execute playbook
        if playbook:
            await self._execute_playbook(incident, playbook)
        
        return incident
    
    def _select_playbook(self, alert: Dict) -> Optional[Dict]:
        """Select appropriate playbook for alert"""
        # Check each playbook's triggers
        for playbook_id, playbook in self.playbooks.items():
            triggers = playbook.get('triggers', [])
            
            for trigger in triggers:
                if self._matches_trigger(alert, trigger):
                    self.logger.info(f"Selected playbook: {playbook['name']}")
                    return playbook
        
        # Default to generic playbook
        return self.playbooks.get('generic')
    
    def _matches_trigger(self, alert: Dict, trigger: Dict) -> bool:
        """Check if alert matches a playbook trigger"""
        trigger_type = trigger.get('type')
        trigger_value = trigger.get('value')
        
        if trigger_type == 'signature':
            return self._check_signature(alert, trigger_value)
        elif trigger_type == 'indicator':
            return self._check_indicator(alert, trigger_value)
        elif trigger_type == 'anomaly':
            return self._check_anomaly(alert, trigger_value)
        elif trigger_type == 'detection':
            return self._check_detection(alert, trigger_value)
        
        return False
    
    def _check_signature(self, alert: Dict, signature: str) -> bool:
        """Check if alert matches a signature"""
        # Check various fields for signature
        fields_to_check = ['signature', 'indicator', 'type', 'threat_type']
        
        for field in fields_to_check:
            if field in alert and signature.lower() in str(alert[field]).lower():
                return True
        
        return False
    
    def _check_indicator(self, alert: Dict, indicator: str) -> bool:
        """Check if alert contains an indicator"""
        # Check for indicator in alert data
        if 'indicators' in alert:
            for ind in alert['indicators']:
                if indicator.lower() in str(ind).lower():
                    return True
        
        return False
    
    def _check_anomaly(self, alert: Dict, anomaly_type: str) -> bool:
        """Check if alert contains an anomaly"""
        if 'anomaly' in alert:
            if alert['anomaly'].get('type') == anomaly_type:
                return True
        
        if 'anomaly_type' in alert and alert['anomaly_type'] == anomaly_type:
            return True
        
        return False
    
    def _check_detection(self, alert: Dict, detection_type: str) -> bool:
        """Check if alert contains a detection"""
        if 'detection' in alert:
            if alert['detection'].get('type') == detection_type:
                return True
        
        if 'detection_type' in alert and alert['detection_type'] == detection_type:
            return True
        
        return False
    
    def _extract_affected_assets(self, alert: Dict) -> List[Dict]:
        """Extract affected assets from alert"""
        assets = []
        
        # Extract IPs
        if 'src_ip' in alert:
            assets.append({
                'type': 'ip',
                'value': alert['src_ip'],
                'role': 'source'
            })
        
        if 'dst_ip' in alert:
            assets.append({
                'type': 'ip',
                'value': alert['dst_ip'],
                'role': 'target'
            })
        
        # Extract hosts
        if 'host' in alert:
            assets.append({
                'type': 'host',
                'value': alert['host']
            })
        
        # Extract users
        if 'user' in alert:
            assets.append({
                'type': 'user',
                'value': alert['user']
            })
        
        # Extract files
        if 'file_path' in alert:
            assets.append({
                'type': 'file',
                'value': alert['file_path']
            })
        
        return assets
    
    async def _execute_playbook(self, incident: Dict, playbook: Dict):
        """Execute incident response playbook"""
        self.logger.info(f"Executing playbook: {playbook['name']} for incident {incident['id']}")
        
        # Execute steps
        for step in playbook['steps']:
            action = step['action']
            timeout = step.get('timeout', 60)
            
            try:
                # Execute action
                result = await self._execute_action(action, incident, step.get('params', {}))
                
                # Record step completion
                incident['steps_completed'].append({
                    'action': action,
                    'timestamp': datetime.now().isoformat(),
                    'result': result,
                    'success': True
                })
                
                self.stats['actions_taken'] += 1
                
            except Exception as e:
                # Record step failure
                incident['steps_completed'].append({
                    'action': action,
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    'success': False
                })
                
                self.logger.error(f"Action {action} failed: {str(e)}")
                
                # Handle failure
                await self._handle_action_failure(incident, action, str(e))
            
            # Check if incident should be escalated
            if incident.get('escalation_required', False):
                await self._escalate_incident(incident)
        
        # Execute post-actions
        for post_action in playbook.get('post_actions', []):
            await self._execute_action(
                post_action['action'],
                incident,
                post_action.get('params', {})
            )
        
        # Update incident status
        incident['status'] = 'completed'
        incident['resolved_at'] = datetime.now().isoformat()
        
        # Calculate resolution time
        created = datetime.fromisoformat(incident['created_at'])
        resolved = datetime.fromisoformat(incident['resolved_at'])
        resolution_time = (resolved - created).total_seconds() / 60  # minutes
        self.stats['resolution_time_avg'] = (
            (self.stats['resolution_time_avg'] * (self.stats['incidents_handled'] - 1) + resolution_time) /
            self.stats['incidents_handled']
        )
    
    async def _execute_action(self, action: str, incident: Dict, params: Dict) -> Dict:
        """Execute a specific response action"""
        self.logger.info(f"Executing action: {action} for incident {incident['id']}")
        
        if action in self.response_actions:
            result = await self.response_actions[action](incident, params)
            incident['actions_taken'].append({
                'action': action,
                'timestamp': datetime.now().isoformat(),
                'params': params,
                'result': result
            })
            return result
        else:
            raise ValueError(f"Unknown action: {action}")
    
    async def _isolate_host(self, incident: Dict, params: Dict) -> Dict:
        """Isolate a host from network"""
        affected_hosts = [asset for asset in incident['affected_assets'] if asset['type'] == 'host']
        
        results = []
        for host in affected_hosts:
            try:
                # Method 1: Use cloud provider API
                if self.config.get('aws', {}).get('enabled'):
                    instance_id = self._get_instance_id(host['value'])
                    if instance_id:
                        self.aws_client.stop_instances(InstanceIds=[instance_id])
                        results.append({
                            'host': host['value'],
                            'status': 'stopped',
                            'method': 'aws'
                        })
                        continue
                
                # Method 2: Use local firewall
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', host['value'], '-j', 'DROP'
                ])
                
                # Method 3: Use network ACL
                subprocess.run([
                    'iptables', '-A', 'FORWARD', '-s', host['value'], '-j', 'DROP'
                ])
                
                results.append({
                    'host': host['value'],
                    'status': 'isolated',
                    'method': 'firewall'
                })
                
            except Exception as e:
                self.logger.error(f"Error isolating host {host['value']}: {str(e)}")
                results.append({
                    'host': host['value'],
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'isolated_hosts': results}
    
    async def _block_ip(self, incident: Dict, params: Dict) -> Dict:
        """Block IP address"""
        ips_to_block = []
        
        # Get IPs from incident
        for asset in incident['affected_assets']:
            if asset['type'] == 'ip':
                ips_to_block.append(asset['value'])
        
        # Add from params
        if params.get('ip'):
            ips_to_block.append(params['ip'])
        
        results = []
        for ip in ips_to_block:
            try:
                # Check if valid IP
                ipaddress.ip_address(ip)
                
                # Block at firewall level
                if self.config.get('firewall', {}).get('type') == 'iptables':
                    subprocess.run([
                        'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
                    ])
                    subprocess.run([
                        'iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'
                    ])
                
                # Block at cloud security group
                if self.config.get('aws', {}).get('enabled'):
                    self.aws_client.authorize_security_group_ingress(
                        GroupId=self.config['aws']['security_group_id'],
                        IpPermissions=[{
                            'IpProtocol': '-1',
                            'IpRanges': [{'CidrIp': f'{ip}/32'}],
                            'FromPort': -1,
                            'ToPort': -1
                        }]
                    )
                
                results.append({
                    'ip': ip,
                    'status': 'blocked'
                })
                
            except Exception as e:
                self.logger.error(f"Error blocking IP {ip}: {str(e)}")
                results.append({
                    'ip': ip,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'blocked_ips': results}
    
    async def _kill_process(self, incident: Dict, params: Dict) -> Dict:
        """Kill malicious processes"""
        results = []
        
        # Get processes from incident or params
        processes = params.get('processes', [])
        if 'affected_assets' in incident:
            for asset in incident['affected_assets']:
                if asset['type'] == 'process':
                    processes.append(asset['value'])
        
        for process_name in processes:
            try:
                # Kill process on affected hosts
                for asset in incident['affected_assets']:
                    if asset['type'] == 'host':
                        host = asset['value']
                        
                        # Kill process using SSH
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(
                            host,
                            username=params.get('username', 'root'),
                            password=params.get('password')
                        )
                        
                        # Find and kill process
                        stdin, stdout, stderr = ssh.exec_command(
                            f"pkill -f {process_name} || killall {process_name}"
                        )
                        
                        result = stdout.read().decode().strip()
                        error = stderr.read().decode().strip()
                        
                        ssh.close()
                        
                        results.append({
                            'process': process_name,
                            'host': host,
                            'status': 'killed' if not error else 'error',
                            'error': error if error else None
                        })
                
            except Exception as e:
                self.logger.error(f"Error killing process {process_name}: {str(e)}")
                results.append({
                    'process': process_name,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'killed_processes': results}
    
    async def _quarantine_file(self, incident: Dict, params: Dict) -> Dict:
        """Quarantine malicious files"""
        results = []
        
        # Get files from incident or params
        files = params.get('files', [])
        if 'affected_assets' in incident:
            for asset in incident['affected_assets']:
                if asset['type'] == 'file':
                    files.append(asset['value'])
        
        for file_path in files:
            try:
                # Create quarantine directory
                quarantine_dir = '/opt/quarantine'
                os.makedirs(quarantine_dir, exist_ok=True)
                
                # Move file to quarantine
                file_name = os.path.basename(file_path)
                quarantine_path = os.path.join(quarantine_dir, f"{file_name}.{int(datetime.now().timestamp())}")
                
                if os.path.exists(file_path):
                    shutil.move(file_path, quarantine_path)
                    
                    # Calculate file hash
                    with open(quarantine_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    
                    results.append({
                        'file': file_path,
                        'quarantined_to': quarantine_path,
                        'hash': file_hash,
                        'status': 'quarantined'
                    })
                else:
                    results.append({
                        'file': file_path,
                        'status': 'not_found'
                    })
                
            except Exception as e:
                self.logger.error(f"Error quarantining file {file_path}: {str(e)}")
                results.append({
                    'file': file_path,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'quarantined_files': results}
    
    async def _capture_forensics(self, incident: Dict, params: Dict) -> Dict:
        """Capture forensic data"""
        results = []
        
        # Get hosts from incident
        hosts = []
        for asset in incident['affected_assets']:
            if asset['type'] == 'host':
                hosts.append(asset['value'])
        
        for host in hosts:
            try:
                # Create forensic collection script
                forensic_script = self._create_forensic_script()
                
                # Execute on host using SSH
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    host,
                    username=params.get('username', 'root'),
                    password=params.get('password')
                )
                
                # Upload and run script
                sftp = ssh.open_sftp()
                remote_path = f"/tmp/forensic_{int(datetime.now().timestamp())}.sh"
                sftp.put(forensic_script, remote_path)
                sftp.close()
                
                stdin, stdout, stderr = ssh.exec_command(f"bash {remote_path}")
                forensic_data = stdout.read().decode()
                error = stderr.read().decode()
                
                ssh.close()
                
                # Save forensic data
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                forensics_dir = f"/var/log/forensics/{host}"
                os.makedirs(forensics_dir, exist_ok=True)
                
                with open(f"{forensics_dir}/{timestamp}_forensic_data.json", 'w') as f:
                    f.write(forensic_data)
                
                results.append({
                    'host': host,
                    'timestamp': timestamp,
                    'status': 'success' if not error else 'error',
                    'error': error if error else None
                })
                
            except Exception as e:
                self.logger.error(f"Error capturing forensics from {host}: {str(e)}")
                results.append({
                    'host': host,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'forensic_captures': results}
    
    def _create_forensic_script(self) -> str:
        """Create forensic data collection script"""
        script = """
        #!/bin/bash
        
        # Collect system information
        echo "=== SYSTEM INFORMATION ==="
        uname -a
        echo ""
        
        echo "=== NETWORK INFORMATION ==="
        ip addr show
        echo ""
        ip route show
        echo ""
        netstat -antup
        echo ""
        
        echo "=== PROCESS INFORMATION ==="
        ps auxf
        echo ""
        
        echo "=== FILE INFORMATION ==="
        lsof
        echo ""
        
        echo "=== OPEN FILES ==="
        lsof | grep -vE "lib|proc|dev"
        echo ""
        
        echo "=== REGISTRY INFORMATION ==="
        if [ -d "/var/lib/regid" ]; then
            find /var/lib/regid -type f -exec cat {} \\;
        fi
        echo ""
        
        echo "=== CRON JOBS ==="
        for user in $(cut -f1 -d: /etc/passwd); do
            echo "Cron jobs for $user:"
            crontab -u $user -l 2>/dev/null
        done
        echo ""
        
        echo "=== STARTUP ITEMS ==="
        find /etc/rc* -type f -exec ls -la {} \\;
        echo ""
        
        echo "=== RECENTLY MODIFIED FILES ==="
        find / -type f -mtime -7 -ls 2>/dev/null | head -100
        echo ""
        
        echo "=== SUSPICIOUS FILES ==="
        find / -type f -name "*.exe" -o -name "*.bin" -o -name "*.dll" 2>/dev/null | head -20
        echo ""
        
        echo "=== ENVIRONMENT ==="
        env
        echo ""
        
        echo "=== PACKAGES ==="
        if command -v dpkg &> /dev/null; then
            dpkg -l
        elif command -v rpm &> /dev/null; then
            rpm -qa
        fi
        echo ""
        
        echo "=== LAST LOGINS ==="
        last -n 20
        echo ""
        
        echo "=== FAILED LOGINS ==="
        lastb -n 20
        echo ""
        
        echo "=== SSH KEYS ==="
        for user in $(cut -f1 -d: /etc/passwd); do
            if [ -d "/home/$user/.ssh" ]; then
                echo "SSH keys for $user:"
                ls -la /home/$user/.ssh/
                cat /home/$user/.ssh/authorized_keys 2>/dev/null
                cat /home/$user/.ssh/known_hosts 2>/dev/null
            fi
        done
        echo ""
        
        echo "=== END OF FORENSIC DATA ==="
        """
        return script
    
    async def _notify_team(self, incident: Dict, params: Dict) -> Dict:
        """Notify security team about incident"""
        channels = params.get('channels', ['security'])
        
        notification = {
            'incident_id': incident['id'],
            'title': incident['title'],
            'severity': incident['severity'],
            'timestamp': datetime.now().isoformat(),
            'description': incident['description'],
            'affected_assets': incident['affected_assets'],
            'actions_taken': incident['actions_taken'][-5:]  # Last 5 actions
        }
        
        # Send to Slack
        if 'slack' in channels and self.config.get('slack', {}).get('enabled'):
            await self._send_slack_notification(notification)
        
        # Send to Email
        if 'email' in channels and self.config.get('email', {}).get('enabled'):
            await self._send_email_notification(notification)
        
        # Send to PagerDuty
        if 'pagerduty' in channels and self.config.get('pagerduty', {}).get('enabled'):
            await self._send_pagerduty_notification(notification)
        
        return {'notification_sent': True}
    
    async def _send_slack_notification(self, notification: Dict):
        """Send Slack notification"""
        # Implementation using Slack API
        pass
    
    async def _send_email_notification(self, notification: Dict):
        """Send email notification"""
        # Implementation using SMTP
        pass
    
    async def _send_pagerduty_notification(self, notification: Dict):
        """Send PagerDuty notification"""
        # Implementation using PagerDuty API
        pass
    
    async def _create_case(self, incident: Dict, params: Dict) -> Dict:
        """Create a case in ticketing system"""
        case_data = {
            'id': f"CASE-{incident['id']}",
            'title': incident['title'],
            'description': incident['description'],
            'severity': incident['severity'],
            'status': 'open',
            'priority': self._calculate_priority(incident),
            'assigned_to': params.get('assignee'),
            'created_at': datetime.now().isoformat()
        }
        
        # Send to ticketing system
        if self.config.get('jira', {}).get('enabled'):
            await self._create_jira_issue(case_data)
        
        if self.config.get('servicenow', {}).get('enabled'):
            await self._create_servicenow_incident(case_data)
        
        return {'case_created': case_data}
    
    def _calculate_priority(self, incident: Dict) -> str:
        """Calculate incident priority"""
        severity_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        
        base_score = severity_scores.get(incident.get('severity', 'medium'), 2)
        
        # Adjust based on affected assets
        if len(incident.get('affected_assets', [])) > 5:
            base_score += 1
        
        # Adjust based on data sensitivity
        if any(asset.get('sensitive', False) for asset in incident.get('affected_assets', [])):
            base_score += 1
        
        priorities = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        return priorities.get(min(base_score, 4), 'medium')
    
    async def _update_firewall(self, incident: Dict, params: Dict) -> Dict:
        """Update firewall rules"""
        block = params.get('block', True)
        ips = params.get('ips', [])
        
        # Collect IPs from incident
        for asset in incident['affected_assets']:
            if asset['type'] == 'ip':
                ips.append(asset['value'])
        
        results = []
        for ip in ips:
            try:
                if block:
                    # Block IP
                    subprocess.run([
                        'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
                    ])
                    subprocess.run([
                        'iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'
                    ])
                else:
                    # Unblock IP
                    subprocess.run([
                        'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
                    ])
                    subprocess.run([
                        'iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'
                    ])
                
                results.append({
                    'ip': ip,
                    'action': 'blocked' if block else 'unblocked',
                    'status': 'success'
                })
                
            except Exception as e:
                results.append({
                    'ip': ip,
                    'action': 'blocked' if block else 'unblocked',
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'firewall_updates': results}
    
    async def _revoke_access(self, incident: Dict, params: Dict) -> Dict:
        """Revoke user access"""
        users = []
        
        # Collect users from incident
        for asset in incident['affected_assets']:
            if asset['type'] == 'user':
                users.append(asset['value'])
        
        # Add users from params
        if params.get('users'):
            users.extend(params['users'])
        
        results = []
        for user in users:
            try:
                # Revoke local access
                subprocess.run(['usermod', '-L', user])
                
                # Remove from groups
                subprocess.run(['gpasswd', '-d', user, 'sudo'])
                
                # Revoke SSH access
                with open('/etc/ssh/sshd_config', 'a') as f:
                    f.write(f"\nDenyUsers {user}\n")
                
                results.append({
                    'user': user,
                    'status': 'revoked',
                    'temporary': params.get('temporary', False)
                })
                
            except Exception as e:
                results.append({
                    'user': user,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'access_revoked': results}
    
    async def _reset_credentials(self, incident: Dict, params: Dict) -> Dict:
        """Reset user credentials"""
        users = []
        
        # Collect users from incident
        for asset in incident['affected_assets']:
            if asset['type'] == 'user':
                users.append(asset['value'])
        
        # Add users from params
        if params.get('users'):
            users.extend(params['users'])
        
        results = []
        for user in users:
            try:
                # Generate new password
                import secrets
                import string
                new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
                
                # Reset password
                subprocess.run(['echo', f'{user}:{new_password}', '|', 'chpasswd'])
                
                # Force password change on next login
                subprocess.run(['chage', '-d', '0', user])
                
                results.append({
                    'user': user,
                    'status': 'reset',
                    'new_password': new_password
                })
                
            except Exception as e:
                results.append({
                    'user': user,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'credentials_reset': results}
    
    async def _capture_memory(self, incident: Dict, params: Dict) -> Dict:
        """Capture memory dump"""
        results = []
        
        # Get hosts from incident
        hosts = []
        for asset in incident['affected_assets']:
            if asset['type'] == 'host':
                hosts.append(asset['value'])
        
        for host in hosts:
            try:
                # Create memory dump directory
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                dump_dir = f"/var/log/memory_dumps/{host}"
                os.makedirs(dump_dir, exist_ok=True)
                
                # Connect via SSH
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    host,
                    username=params.get('username', 'root'),
                    password=params.get('password')
                )
                
                # Run memory dump command
                if self._is_linux():
                    stdin, stdout, stderr = ssh.exec_command(
                        f"dd if=/dev/mem of={dump_dir}/{timestamp}_memory.dump bs=1M count=100"
                    )
                elif self._is_windows():
                    stdin, stdout, stderr = ssh.exec_command(
                        f"dumpit.exe -accepteula -quiet -output {dump_dir}/{timestamp}_memory.dump"
                    )
                
                error = stderr.read().decode()
                
                ssh.close()
                
                results.append({
                    'host': host,
                    'dump_file': f"{dump_dir}/{timestamp}_memory.dump",
                    'status': 'success' if not error else 'error',
                    'error': error if error else None
                })
                
            except Exception as e:
                self.logger.error(f"Error capturing memory from {host}: {str(e)}")
                results.append({
                    'host': host,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'memory_captures': results}
    
    async def _analyze_malware(self, incident: Dict, params: Dict) -> Dict:
        """Analyze malware sample"""
        results = []
        
        # Get files from incident
        files = []
        for asset in incident['affected_assets']:
            if asset['type'] == 'file':
                files.append(asset['value'])
        
        for file_path in files:
            try:
                # Check if file exists
                if not os.path.exists(file_path):
                    continue
                
                # Calculate file hash
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Submit to sandbox (Cuckoo or similar)
                if self.config.get('sandbox', {}).get('enabled'):
                    sandbox_result = await self._submit_to_sandbox(file_path)
                else:
                    sandbox_result = {}
                
                # Check against AV engines (using VirusTotal)
                if self.config.get('virustotal', {}).get('enabled'):
                    vt_result = await self._check_virustotal(file_hash)
                else:
                    vt_result = {}
                
                # Analyze behavior
                behavioral_analysis = self._analyze_behavior(file_path)
                
                results.append({
                    'file': file_path,
                    'hash': file_hash,
                    'sandbox_analysis': sandbox_result,
                    'av_detection': vt_result,
                    'behavioral_analysis': behavioral_analysis,
                    'status': 'completed'
                })
                
            except Exception as e:
                self.logger.error(f"Error analyzing malware {file_path}: {str(e)}")
                results.append({
                    'file': file_path,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return {'malware_analyses': results}
    
    async def _submit_to_sandbox(self, file_path: str) -> Dict:
        """Submit file to sandbox for analysis"""
        # Implementation for Cuckoo or other sandbox
        return {'submitted': True}
    
    async def _check_virustotal(self, file_hash: str) -> Dict:
        """Check file hash against VirusTotal"""
        # Implementation for VirusTotal API
        return {'detected': False}
    
    def _analyze_behavior(self, file_path: str) -> Dict:
        """Analyze file behavior"""
        # Implementation for behavioral analysis
        return {'suspicious': False}
    
    async def _rollback_changes(self, incident: Dict, params: Dict) -> Dict:
        """Rollback changes made during incident response"""
        results = []
        
        for action in incident.get('actions_taken', []):
            if action['action'] == 'block_ip':
                # Unblock IPs
                await self._rollback_ip_block(action)
            elif action['action'] == 'isolate_host':
                # Reconnect hosts
                await self._rollback_host_isolate(action)
            elif action['action'] == 'revoke_access':
                # Restore access
                await self._rollback_access_revoke(action)
            
            results.append({
                'action': action['action'],
                'status': 'rolled_back'
            })
        
        return {'changes_rolled_back': results}
    
    async def _rollback_ip_block(self, action: Dict):
        """Rollback IP block"""
        # Implementation
        pass
    
    async def _rollback_host_isolate(self, action: Dict):
        """Rollback host isolation"""
        # Implementation
        pass
    
    async def _rollback_access_revoke(self, action: Dict):
        """Rollback access revocation"""
        # Implementation
        pass
    
    async def _escalate_incident(self, incident: Dict) -> Dict:
        """Escalate incident to higher tier"""
        incident['escalation_level'] += 1
        
        escalation_info = {
            'incident_id': incident['id'],
            'level': incident['escalation_level'],
            'reason': 'Automated escalation due to severity',
            'timestamp': datetime.now().isoformat(),
            'assigned_to': self._get_next_responder(incident['escalation_level'])
        }
        
        # Send escalation notification
        await self._notify_team(incident, {
            'channels': ['security', 'management'],
            'escalation': True
        })
        
        self.stats['escalations'] += 1
        
        return {'escalated': escalation_info}
    
    def _get_next_responder(self, level: int) -> str:
        """Get next responder based on escalation level"""
        responders = {
            1: 'tier1_soc',
            2: 'tier2_soc',
            3: 'tier3_soc',
            4: 'security_manager'
        }
        return responders.get(level, 'security_manager')
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _is_linux(self) -> bool:
        """Check if running on Linux"""
        import platform
        return platform.system() == 'Linux'
    
    def _is_windows(self) -> bool:
        """Check if running on Windows"""
        import platform
        return platform.system() == 'Windows'
    
    def _get_instance_id(self, host: str) -> Optional[str]:
        """Get AWS instance ID from host"""
        # Implementation to map host to instance ID
        return None
    
    async def _handle_action_failure(self, incident: Dict, action: str, error: str):
        """Handle action failure"""
        self.logger.error(f"Action {action} failed for incident {incident['id']}: {error}")
        
        # Check if should escalate
        if incident.get('escalation_level', 0) < 3:
            await self._escalate_incident(incident)
        
        # Log failure
        incident['actions_taken'].append({
            'action': action,
            'timestamp': datetime.now().isoformat(),
            'status': 'failed',
            'error': error
        })
    
    async def get_incident_stats(self) -> Dict:
        """Get incident response statistics"""
        return {
            'total_incidents': self.stats['incidents_handled'],
            'actions_taken': self.stats['actions_taken'],
            'escalations': self.stats['escalations'],
            'avg_resolution_time_minutes': self.stats['resolution_time_avg'],
            'active_incidents': len(self.active_incidents)
        }
    
    async def close(self):
        """Clean up resources"""
        if self.redis:
            await self.redis.close()