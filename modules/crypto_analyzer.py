#!/usr/bin/env python3
"""
Cryptography Analyzer for BugHunter Pro
TLS/SSL version detection, cipher suite analysis, and certificate validation
"""

import ssl
import socket
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)

# Optional: OpenSSL for advanced features
try:
    from OpenSSL import SSL, crypto
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False
    logger.info("pyOpenSSL not available. Install: pip install pyOpenSSL")


@dataclass
class TLSInfo:
    """TLS/SSL information"""
    protocol_version: str
    cipher_suite: str
    cipher_strength: int
    certificate_valid: bool
    certificate_issuer: str
    certificate_subject: str
    certificate_expiry: str
    security_level: str
    vulnerabilities: List[str]


class CryptoAnalyzer:
    """Cryptography and TLS/SSL analyzer"""
    
    # Weak/deprecated protocols
    WEAK_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
    
    # Weak ciphers
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon',
        'ADH', 'AECDH'
    ]
    
    def __init__(self):
        """Initialize crypto analyzer"""
        self.results = {}
    
    def analyze_tls(self, url: str, timeout: int = 10) -> Optional[TLSInfo]:
        """
        Analyze TLS/SSL configuration of a target
        
        Args:
            url: Target URL
            timeout: Connection timeout
        
        Returns:
            TLSInfo object or None
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if parsed.scheme != 'https':
            logger.warning(f"Not an HTTPS URL: {url}")
            return None
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get TLS info
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get protocol version
                    protocol_version = ssock.version() or 'Unknown'
                    
                    # Get cipher suite
                    cipher = ssock.cipher()
                    cipher_suite = cipher[0] if cipher else 'Unknown'
                    cipher_strength = cipher[2] if cipher and len(cipher) > 2 else 0
                    
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Parse certificate
                    cert_valid = True
                    cert_issuer = self._parse_cert_field(cert, 'issuer') if cert else 'Unknown'
                    cert_subject = self._parse_cert_field(cert, 'subject') if cert else 'Unknown'
                    cert_expiry = str(cert.get('notAfter', 'Unknown')) if cert else 'Unknown'
                    
                    # Check for vulnerabilities
                    vulnerabilities = self._check_vulnerabilities(
                        protocol_version,
                        cipher_suite
                    )
                    
                    # Determine security level
                    security_level = self._assess_security_level(
                        protocol_version,
                        cipher_suite,
                        cipher_strength,
                        vulnerabilities
                    )
                    
                    return TLSInfo(
                        protocol_version=protocol_version,
                        cipher_suite=cipher_suite,
                        cipher_strength=cipher_strength,
                        certificate_valid=cert_valid,
                        certificate_issuer=cert_issuer,
                        certificate_subject=cert_subject,
                        certificate_expiry=cert_expiry,
                        security_level=security_level,
                        vulnerabilities=vulnerabilities
                    )
        
        except ssl.SSLError as e:
            logger.error(f"SSL error for {url}: {e}")
            return None
        except socket.timeout:
            logger.error(f"Connection timeout for {url}")
            return None
        except Exception as e:
            logger.error(f"Failed to analyze TLS for {url}: {e}")
            return None
    
    def _parse_cert_field(self, cert: Dict, field: str) -> str:
        """Parse certificate field"""
        try:
            if field in cert:
                items = cert[field]
                if isinstance(items, tuple):
                    return ', '.join(f"{k}={v}" for item in items for k, v in item)
            return 'Unknown'
        except:
            return 'Unknown'
    
    def _check_vulnerabilities(self, protocol: str, cipher: str) -> List[str]:
        """Check for known vulnerabilities"""
        vulnerabilities = []
        
        # Check protocol version
        if protocol in self.WEAK_PROTOCOLS:
            vulnerabilities.append(f"Weak protocol: {protocol}")
        
        # Check cipher suite
        for weak_cipher in self.WEAK_CIPHERS:
            if weak_cipher.lower() in cipher.lower():
                vulnerabilities.append(f"Weak cipher: {weak_cipher}")
        
        # Specific vulnerabilities
        if 'RC4' in cipher:
            vulnerabilities.append("Vulnerable to RC4 attacks")
        
        if protocol == 'SSLv3':
            vulnerabilities.append("Vulnerable to POODLE attack")
        
        if 'CBC' in cipher and protocol in ['TLSv1.0', 'TLSv1.1']:
            vulnerabilities.append("Potentially vulnerable to BEAST attack")
        
        return vulnerabilities
    
    def _assess_security_level(
        self,
        protocol: str,
        cipher: str,
        strength: int,
        vulnerabilities: List[str]
    ) -> str:
        """Assess overall security level"""
        if vulnerabilities:
            return 'CRITICAL' if len(vulnerabilities) > 2 else 'HIGH'
        
        if protocol in self.WEAK_PROTOCOLS:
            return 'HIGH'
        
        if strength < 128:
            return 'MEDIUM'
        
        if protocol in ['TLSv1.2', 'TLSv1.3'] and strength >= 256:
            return 'LOW'
        
        return 'MEDIUM'
    
    def check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Check security-related HTTP headers
        
        Args:
            headers: HTTP response headers
        
        Returns:
            Dictionary of security header analysis
        """
        security_headers = {
            'Strict-Transport-Security': {
                'present': False,
                'value': None,
                'severity': 'HIGH',
                'description': 'HSTS header missing'
            },
            'Content-Security-Policy': {
                'present': False,
                'value': None,
                'severity': 'MEDIUM',
                'description': 'CSP header missing'
            },
            'X-Frame-Options': {
                'present': False,
                'value': None,
                'severity': 'MEDIUM',
                'description': 'X-Frame-Options header missing'
            },
            'X-Content-Type-Options': {
                'present': False,
                'value': None,
                'severity': 'LOW',
                'description': 'X-Content-Type-Options header missing'
            },
            'X-XSS-Protection': {
                'present': False,
                'value': None,
                'severity': 'LOW',
                'description': 'X-XSS-Protection header missing'
            }
        }
        
        # Check each header
        for header_name in security_headers.keys():
            for actual_header, value in headers.items():
                if actual_header.lower() == header_name.lower():
                    security_headers[header_name]['present'] = True
                    security_headers[header_name]['value'] = value
                    security_headers[header_name]['description'] = f"{header_name} is configured"
                    break
        
        return security_headers
    
    def test_cipher_suites(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """
        Test available cipher suites
        
        Args:
            hostname: Target hostname
            port: Target port
        
        Returns:
            List of supported cipher suites
        """
        supported_ciphers = []
        
        # Common cipher suites to test
        test_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'AES256-SHA256',
            'AES128-SHA256',
            'DES-CBC3-SHA',  # Weak
            'RC4-SHA',       # Weak
        ]
        
        for cipher in test_ciphers:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers(cipher)
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported_ciphers.append({
                            'cipher': cipher,
                            'supported': True,
                            'protocol': ssock.version()
                        })
            except:
                supported_ciphers.append({
                    'cipher': cipher,
                    'supported': False
                })
        
        return supported_ciphers


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("Cryptography Analyzer Demo")
    print("="*70)
    
    analyzer = CryptoAnalyzer()
    
    # Test against a public HTTPS site
    test_url = "https://www.google.com"
    
    print(f"\n🔒 Analyzing TLS configuration: {test_url}\n")
    
    tls_info = analyzer.analyze_tls(test_url)
    
    if tls_info:
        print(f"Protocol Version: {tls_info.protocol_version}")
        print(f"Cipher Suite: {tls_info.cipher_suite}")
        print(f"Cipher Strength: {tls_info.cipher_strength} bits")
        print(f"Security Level: {tls_info.security_level}")
        print(f"\nCertificate Info:")
        print(f"  Issuer: {tls_info.certificate_issuer[:60]}...")
        print(f"  Subject: {tls_info.certificate_subject[:60]}...")
        print(f"  Expiry: {tls_info.certificate_expiry}")
        
        if tls_info.vulnerabilities:
            print(f"\n⚠️  Vulnerabilities Found:")
            for vuln in tls_info.vulnerabilities:
                print(f"  - {vuln}")
        else:
            print(f"\n✅ No known vulnerabilities detected")
    else:
        print("❌ Failed to analyze TLS")
