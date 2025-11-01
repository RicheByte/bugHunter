#!/usr/bin/env python3
"""
Advanced Features Demo for BugHunter Pro
Demonstrates Phase 3 & 4 features: evasion, ML, crypto, cloud
"""

import asyncio
import logging
from modules.evasion_advanced import AdvancedEvasion
from modules.ml_vuln_predictor import MLVulnPredictor
from modules.crypto_analyzer import CryptoAnalyzer
from modules.cloud_metadata_scanner import CloudMetadataScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def demo_evasion():
    """Demonstrate advanced evasion techniques"""
    print("\n" + "="*70)
    print("🎭 ADVANCED EVASION TECHNIQUES")
    print("="*70 + "\n")
    
    evasion = AdvancedEvasion()
    
    # SQL injection payload
    sql_payload = "' OR 1=1--"
    print(f"Original Payload: {sql_payload}\n")
    
    variants = evasion.generate_variants(sql_payload, vuln_type='sql')
    print(f"Generated {len(variants)} evasion variants:\n")
    
    for i, variant in enumerate(variants[:5], 1):
        print(f"{i}. Encoding: {variant['encoding']}")
        print(f"    Payload: {variant['payload']}")
    
    # XSS payload
    print("\n" + "-"*70 + "\n")
    xss_payload = "<script>alert('XSS')</script>"
    print(f"XSS Payload: {xss_payload}\n")
    
    xss_variants = evasion.generate_variants(xss_payload, vuln_type='xss')
    for i, variant in enumerate(xss_variants[:3], 1):
        print(f"{i}. Encoding: {variant['encoding']}")
        print(f"    Payload: {variant['payload']}")


def demo_ml_predictor():
    """Demonstrate ML vulnerability prediction"""
    print("\n" + "="*70)
    print("🤖 ML VULNERABILITY PREDICTION")
    print("="*70 + "\n")
    
    predictor = MLVulnPredictor()
    
    # Generate training data and train model
    print("Training ML model with synthetic data...\n")
    X, y = predictor._generate_training_data()
    predictor.train(X, y)
    
    # Test predictions
    baseline_response = {
        'status_code': 200,
        'response_body': 'Welcome to our website',
        'response_time': 0.1,
        'headers': {'Content-Type': 'text/html'}
    }
    
    test_cases = [
        {
            'status_code': 500,
            'response_body': 'MySQL syntax error near',
            'response_time': 0.5,
            'headers': {}
        },
        {
            'status_code': 200,
            'response_body': 'Welcome to our website',
            'response_time': 0.1,
            'headers': {'Content-Type': 'text/html'}
        },
        {
            'status_code': 403,
            'response_body': '<script>alert(1)</script>',
            'response_time': 0.2,
            'headers': {}
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        result = predictor.predict(baseline_response, test_case)
        print(f"Test Case {i}:")
        print(f"  Status: {test_case['status_code']}")
        print(f"  Body: {test_case['response_body'][:50]}...")
        print(f"  Vulnerable: {result.is_vulnerable}")
        print(f"  Confidence: {result.confidence:.2%}")
        print(f"  Predicted Type: {result.vulnerability_type or 'None'}")
        print()


async def demo_crypto_analyzer():
    """Demonstrate TLS/SSL analysis"""
    print("\n" + "="*70)
    print("🔐 TLS/SSL SECURITY ANALYSIS")
    print("="*70 + "\n")
    
    analyzer = CryptoAnalyzer()
    
    # Test popular websites
    test_urls = [
        'https://www.google.com',
        'https://github.com',
    ]
    
    for url in test_urls:
        print(f"Analyzing {url}...\n")
        
        result = analyzer.analyze_tls(url)
        
        if result:
            print(f"  Protocol: {result.protocol_version}")
            print(f"  Cipher: {result.cipher_suite}")
            print(f"  Certificate Expiry: {result.certificate_expiry}")
            
            if result.vulnerabilities:
                print(f"  Vulnerabilities: {', '.join(result.vulnerabilities)}")
            else:
                print("  Vulnerabilities: None detected")
        else:
            print("  Could not analyze (not HTTPS or connection failed)")
        
        print()


def demo_cloud_scanner():
    """Demonstrate cloud metadata scanning"""
    print("\n" + "="*70)
    print("☁️  CLOUD METADATA SCANNER")
    print("="*70 + "\n")
    
    scanner = CloudMetadataScanner()
    
    # Check if running on cloud
    print("Checking for cloud environment...\n")
    findings = scanner.test_direct_metadata_access()
    
    if findings:
        print(f"✅ Cloud Environment Detected!\n")
        for finding in findings:
            print(f"  Provider: {finding.cloud_provider}")
            print(f"  Severity: {finding.severity}")
            print(f"  Description: {finding.description}")
            print()
    else:
        print("ℹ️  Not running on cloud or metadata service blocked\n")
    
    # Generate sample SSRF payloads
    print("Sample SSRF Payloads for Cloud Metadata:\n")
    payloads = scanner.generate_ssrf_payloads()
    
    print("AWS EC2 Metadata:")
    aws_payloads = [p for p in payloads if '169.254.169.254' in p and 'api-version' not in p][:2]
    for p in aws_payloads:
        print(f"  {p}")
    
    print("\nAzure VM Metadata:")
    azure_payloads = [p for p in payloads if 'api-version' in p][:2]
    for p in azure_payloads:
        print(f"  {p}")
    
    print("\nGCP Compute Metadata:")
    gcp_payloads = [p for p in payloads if 'google' in p.lower()][:2]
    for p in gcp_payloads:
        print(f"  {p}")


def main():
    """Run all advanced feature demos"""
    print("\n" + "="*70)
    print("🚀 BUGHUNTER PRO - ADVANCED FEATURES DEMO")
    print("="*70)
    print("\nPhase 3 & 4 Features Showcase:")
    print("  • Advanced Evasion Techniques (WAF/IPS Bypass)")
    print("  • ML-Based Vulnerability Prediction")
    print("  • TLS/SSL Security Analysis")
    print("  • Cloud Metadata Scanning")
    print()
    
    # Phase 3: Advanced Evasion
    demo_evasion()
    
    # Phase 3: ML Prediction
    demo_ml_predictor()
    
    # Phase 4: Crypto Analysis
    print("\nRunning async TLS analysis...")
    asyncio.run(demo_crypto_analyzer())
    
    # Phase 4: Cloud Scanning
    demo_cloud_scanner()
    
    print("\n" + "="*70)
    print("✅ DEMO COMPLETE")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
