# Alert Rules Configuration
RULES = {
    'port_scan': {
        'name': 'Port Scan Detected',
        'severity': 'high',
        'condition': {
            'field': 'dst_port',
            'operator': 'unique_count_gt',
            'value': 20,
            'time_window': 60
        },
        'action': 'block_ip',
        'description': 'Multiple ports scanned from single source'
    },
    
    'data_exfil': {
        'name': 'Data Exfiltration Attempt',
        'severity': 'critical',
        'condition': {
            'field': 'bytes_out',
            'operator': 'gt',
            'value': 1000000000,  # 1GB
            'time_window': 300
        },
        'action': 'isolate_host',
        'description': 'Large data transfer detected'
    },
    
    'brute_force': {
        'name': 'Brute Force Attack',
        'severity': 'high',
        'condition': {
            'field': 'src_ip',
            'operator': 'count_gt',
            'value': 10,
            'time_window': 60,
            'pattern': 'failed_login'
        },
        'action': 'block_ip',
        'description': 'Multiple failed login attempts'
    },
    
    'malware': {
        'name': 'Malware Detected',
        'severity': 'critical',
        'condition': {
            'field': 'signature',
            'operator': 'matches',
            'value': ['ransomware', 'trojan', 'worm']
        },
        'action': 'quarantine',
        'description': 'Malware signature detected'
    }
}

def evaluate_rule(rule_name, data):
    """Evaluate if a rule matches the data"""
    rule = RULES.get(rule_name)
    if not rule:
        return False
    
    condition = rule.get('condition', {})
    field = condition.get('field')
    operator = condition.get('operator')
    value = condition.get('value')
    
    if not field or not operator:
        return False
    
    actual_value = data.get(field)
    if actual_value is None:
        return False
    
    if operator == 'gt':
        return actual_value > value
    elif operator == 'lt':
        return actual_value < value
    elif operator == 'eq':
        return actual_value == value
    elif operator == 'matches':
        return any(actual_value.lower().find(v.lower()) != -1 for v in value)
    # Add more operators as needed
    
    return False
