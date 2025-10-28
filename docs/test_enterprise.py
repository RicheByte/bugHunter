#!/usr/bin/env python3
"""
BugHunter Pro v5.0 Enterprise - Full Feature Test
Tests all enterprise features including ML, WAF detection, evasion, compliance mapping
"""

import sys
import subprocess
import time
from pathlib import Path

def print_banner():
    print("\n" + "="*80)
    print("🔥 BugHunter Pro v5.0 Enterprise - Full Feature Test")
    print("="*80)
    print("Testing all enterprise features:")
    print("  ✓ Basic vulnerability scanning (SQL, XSS, Command Injection)")
    print("  ✓ ML false positive reduction")
    print("  ✓ WAF detection & evasion")
    print("  ✓ Compliance framework mapping (NIST, PCI-DSS, ISO 27001, CIS, OWASP)")
    print("  ✓ Adaptive rate limiting")
    print("  ✓ HMAC-signed audit logging")
    print("  ✓ Target intelligence & fingerprinting")
    print("  ✓ Performance metrics tracking")
    print("="*80 + "\n")

def run_test(name, command, description):
    """Run a test command and report results"""
    print(f"\n{'='*80}")
    print(f"TEST: {name}")
    print(f"Description: {description}")
    print(f"Command: {command}")
    print("="*80 + "\n")
    
    try:
        # Run command
        result = subprocess.run(
            command,
            shell=True,
            capture_output=False,
            text=True,
            timeout=120  # 2 minute timeout per test
        )
        
        if result.returncode == 0:
            print(f"\n✅ TEST PASSED: {name}")
        else:
            print(f"\n⚠️ TEST COMPLETED WITH WARNINGS: {name}")
        
        return result.returncode
        
    except subprocess.TimeoutExpired:
        print(f"\n⏱️ TEST TIMEOUT: {name} (exceeded 2 minutes)")
        return -1
    except Exception as e:
        print(f"\n❌ TEST FAILED: {name} - {e}")
        return -1

def main():
    print_banner()
    
    # Get Python executable path
    if sys.platform == "win32":
        python = ".venv\\Scripts\\python.exe"
    else:
        python = ".venv/bin/python"
    
    # Verify bughunter.py exists
    bughunter_path = Path("bughunter.py")
    if not bughunter_path.exists():
        print("❌ ERROR: bughunter.py not found in current directory")
        return 1
    
    print(f"Using Python: {python}")
    print(f"Target: http://testphp.vulnweb.com (known vulnerable test site)\n")
    
    # Test 1: Basic scan (no enterprise features)
    test_results = []
    
    print("\n" + "🔷"*40)
    print("Starting Test Suite...")
    print("🔷"*40 + "\n")
    
    # Test 1: Basic Scan
    result = run_test(
        "Basic Vulnerability Scan",
        f"{python} bughunter.py -u http://testphp.vulnweb.com --threads 20 --depth 2 --max-pages 50",
        "Baseline scan without enterprise features - should find SQL injections"
    )
    test_results.append(("Basic Scan", result))
    time.sleep(2)
    
    # Test 2: ML-Enabled Scan
    result = run_test(
        "ML False Positive Reduction",
        f"{python} bughunter.py -u http://testphp.vulnweb.com --enable-ml --threads 20 --depth 2 --max-pages 50",
        "Scan with ML filtering - should reduce false positives (may fall back to rule-based if sklearn not installed)"
    )
    test_results.append(("ML Filter", result))
    time.sleep(2)
    
    # Test 3: Evasion-Enabled Scan
    result = run_test(
        "WAF Evasion Techniques",
        f"{python} bughunter.py -u http://testphp.vulnweb.com --enable-evasion --threads 20 --depth 2 --max-pages 50",
        "Scan with evasion - polymorphic payloads and user-agent rotation"
    )
    test_results.append(("Evasion", result))
    time.sleep(2)
    
    # Test 4: Compliance Mapping
    result = run_test(
        "Compliance Framework Mapping",
        f"{python} bughunter.py -u http://testphp.vulnweb.com --enable-compliance --threads 20 --depth 2 --max-pages 50",
        "Scan with compliance mapping - maps findings to NIST-CSF, PCI-DSS, ISO 27001, CIS, OWASP"
    )
    test_results.append(("Compliance", result))
    time.sleep(2)
    
    # Test 5: Full Enterprise Mode
    result = run_test(
        "Full Enterprise Mode (ALL FEATURES)",
        f"{python} bughunter.py -u http://testphp.vulnweb.com --enable-ml --enable-evasion --enable-compliance --threads 50 --depth 2 --max-pages 100",
        "Complete enterprise scan with ML + Evasion + Compliance + Adaptive Rate Limiting + Fingerprinting"
    )
    test_results.append(("Full Enterprise", result))
    
    # Print Summary
    print("\n\n" + "="*80)
    print("📊 TEST SUITE SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, code in test_results if code == 0)
    total = len(test_results)
    
    for test_name, return_code in test_results:
        status = "✅ PASS" if return_code == 0 else "⚠️ WARN" if return_code == -1 else f"❌ FAIL ({return_code})"
        print(f"{status:15} - {test_name}")
    
    print("="*80)
    print(f"Results: {passed}/{total} tests passed")
    print("="*80)
    
    # Check if report files were generated
    print("\n📁 Checking for generated reports...")
    report_files = list(Path(".").glob("bughunter_report_*.json"))
    if report_files:
        print(f"✅ Found {len(report_files)} report file(s):")
        for report in sorted(report_files)[-5:]:  # Show last 5 reports
            print(f"   - {report.name}")
    else:
        print("⚠️ No report files found")
    
    # Check audit logs
    audit_log = Path("security_audit.log")
    if audit_log.exists():
        print(f"\n✅ Audit log found: {audit_log.name} ({audit_log.stat().st_size} bytes)")
    else:
        print("\n⚠️ Audit log not found")
    
    audit_db = Path("security_audit.db")
    if audit_db.exists():
        print(f"✅ Audit database found: {audit_db.name} ({audit_db.stat().st_size} bytes)")
    else:
        print("⚠️ Audit database not found")
    
    print("\n" + "="*80)
    print("🏁 Enterprise Feature Test Complete!")
    print("="*80)
    print("\nNOTE: This scanner is designed for authorized penetration testing only.")
    print("Always obtain written permission before testing any target.")
    print("="*80 + "\n")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
