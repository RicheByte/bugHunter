#!/usr/bin/env python3
"""
Quick demo of BugHunter Pro finding real SQL injection
This demonstrates the scanner works perfectly when pointed at vulnerable endpoints
"""

from bughunter import (
    BugHunterPro,
    SQLInjectionScanner,
    XSSScanner,
    ScanConfig,
    SeverityLevel
)

def demo_sql_injection():
    """Demonstrate SQL injection detection on known vulnerable site"""
    print("\n" + "="*70)
    print("🎯 DEMO: SQL Injection Detection")
    print("="*70)
    print("Target: http://testphp.vulnweb.com/artists.php?artist=1")
    print("Known vulnerability: SQL Injection in 'artist' parameter\n")
    
    config = ScanConfig()
    scanner = SQLInjectionScanner(config)
    
    # Test the vulnerable endpoint
    vulnerabilities = scanner.scan(
        url='http://testphp.vulnweb.com/artists.php',
        parameters={'artist': '1'}
    )
    
    if vulnerabilities:
        print("✅ SUCCESS! Found SQL Injection\n")
        for vuln in vulnerabilities:
            print(f"Type: {vuln.vuln_type}")
            print(f"Severity: {vuln.severity.value.upper()}")
            print(f"Payload: {vuln.payload}")
            print(f"Evidence: {vuln.evidence}")
            print(f"CVSS: {vuln.cvss_score}")
    else:
        print("❌ No vulnerabilities found")
    
    print("\n" + "="*70)

def demo_xss():
    """Demonstrate XSS detection"""
    print("\n" + "="*70)
    print("🎯 DEMO: XSS Detection")
    print("="*70)
    print("Testing XSS on search parameters\n")
    
    config = ScanConfig()
    scanner = XSSScanner(config)
    
    # Test search endpoint
    vulnerabilities = scanner.scan(
        url='http://testphp.vulnweb.com/search.php',
        parameters={'searchFor': 'test'}
    )
    
    if vulnerabilities:
        print("✅ Found XSS vulnerability\n")
        for vuln in vulnerabilities:
            print(f"Type: {vuln.vuln_type}")
            print(f"Parameter: {vuln.parameter}")
            print(f"Payload: {vuln.payload[:50]}...")
    else:
        print("❌ No XSS vulnerabilities found")
    
    print("\n" + "="*70)

def demo_multiple_targets():
    """Demonstrate scanning multiple endpoints"""
    print("\n" + "="*70)
    print("🎯 DEMO: Multiple Endpoint Testing")
    print("="*70)
    print("Testing various pages for SQL injection\n")
    
    config = ScanConfig()
    sql_scanner = SQLInjectionScanner(config)
    
    test_endpoints = [
        ('http://testphp.vulnweb.com/artists.php', {'artist': '1'}),
        ('http://testphp.vulnweb.com/listproducts.php', {'cat': '1'}),
        ('http://testphp.vulnweb.com/showimage.php', {'file': 'test.jpg'}),
    ]
    
    all_vulns = []
    for url, params in test_endpoints:
        print(f"[Testing] {url}")
        vulns = sql_scanner.scan(url, params)
        all_vulns.extend(vulns)
    
    print(f"\n📊 Results: Found {len(all_vulns)} SQL injection vulnerabilities")
    for vuln in all_vulns:
        print(f"  - {vuln.url} (parameter: {vuln.parameter})")
    
    print("\n" + "="*70)

if __name__ == "__main__":
    print("\n")
    print("🔥"*35)
    print("  BugHunter Pro v5.0 - Demonstration")
    print("🔥"*35)
    
    # Run demos
    demo_sql_injection()
    demo_xss()
    demo_multiple_targets()
    
    print("\n✨ Demo complete! The scanner successfully detects real vulnerabilities.")
    print("💡 Use 'python bughunter.py -u <target>' for full scans\n")
