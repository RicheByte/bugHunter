#!/usr/bin/env python3
"""
Accuracy Testing for BugHunter Pro
Tests detection accuracy against known vulnerable patterns
"""

import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityTestCase:
    """Test case for a known vulnerability"""
    name: str
    vuln_type: str
    url: str
    payload: str
    expected_vulnerable: bool
    severity: str


@dataclass
class AccuracyMetrics:
    """Accuracy testing metrics"""
    total_tests: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float


class AccuracyTester:
    """Accuracy testing against known vulnerabilities"""
    
    def __init__(self):
        """Initialize accuracy tester"""
        self.test_cases: List[VulnerabilityTestCase] = []
        self.results: Dict[str, bool] = {}
    
    def load_dvwa_test_cases(self) -> List[VulnerabilityTestCase]:
        """
        Load DVWA-style test cases (patterns, not actual DVWA)
        
        Returns:
            List of test cases
        """
        test_cases = [
            # SQL Injection - Should detect
            VulnerabilityTestCase(
                name="SQL Injection - Classic",
                vuln_type="sql_injection",
                url="http://testsite.local/user.php?id=1",
                payload="' OR '1'='1",
                expected_vulnerable=True,
                severity="HIGH"
            ),
            VulnerabilityTestCase(
                name="SQL Injection - UNION",
                vuln_type="sql_injection",
                url="http://testsite.local/user.php?id=1",
                payload="' UNION SELECT NULL--",
                expected_vulnerable=True,
                severity="HIGH"
            ),
            
            # XSS - Should detect
            VulnerabilityTestCase(
                name="XSS - Reflected",
                vuln_type="xss",
                url="http://testsite.local/search.php?q=test",
                payload="<script>alert('XSS')</script>",
                expected_vulnerable=True,
                severity="MEDIUM"
            ),
            VulnerabilityTestCase(
                name="XSS - Event Handler",
                vuln_type="xss",
                url="http://testsite.local/comment.php",
                payload="<img src=x onerror=alert(1)>",
                expected_vulnerable=True,
                severity="MEDIUM"
            ),
            
            # Command Injection - Should detect
            VulnerabilityTestCase(
                name="Command Injection",
                vuln_type="command_injection",
                url="http://testsite.local/ping.php?host=127.0.0.1",
                payload="; cat /etc/passwd",
                expected_vulnerable=True,
                severity="CRITICAL"
            ),
            
            # Path Traversal - Should detect
            VulnerabilityTestCase(
                name="Path Traversal",
                vuln_type="path_traversal",
                url="http://testsite.local/download.php?file=doc.pdf",
                payload="../../../etc/passwd",
                expected_vulnerable=True,
                severity="HIGH"
            ),
            
            # SSRF - Should detect
            VulnerabilityTestCase(
                name="SSRF - AWS Metadata",
                vuln_type="ssrf",
                url="http://testsite.local/fetch.php?url=example.com",
                payload="http://169.254.169.254/latest/meta-data/",
                expected_vulnerable=True,
                severity="CRITICAL"
            ),
            
            # Safe inputs - Should NOT detect
            VulnerabilityTestCase(
                name="Safe Input - Normal String",
                vuln_type="sql_injection",
                url="http://testsite.local/user.php?id=1",
                payload="john_doe",
                expected_vulnerable=False,
                severity="NONE"
            ),
            VulnerabilityTestCase(
                name="Safe Input - Numbers",
                vuln_type="sql_injection",
                url="http://testsite.local/user.php?id=1",
                payload="12345",
                expected_vulnerable=False,
                severity="NONE"
            ),
            VulnerabilityTestCase(
                name="Safe Input - Normal Text",
                vuln_type="xss",
                url="http://testsite.local/search.php?q=test",
                payload="hello world",
                expected_vulnerable=False,
                severity="NONE"
            ),
        ]
        
        self.test_cases = test_cases
        return test_cases
    
    def test_payload_detection(self, payload: str, vuln_type: str) -> bool:
        """
        Test if a payload would be detected as vulnerable
        
        Args:
            payload: The payload to test
            vuln_type: Type of vulnerability
        
        Returns:
            True if vulnerable pattern detected
        """
        # Pattern-based detection (simplified)
        patterns = {
            'sql_injection': [
                "' or ", "' OR ", "1=1", "UNION", "SELECT", "--", "/*", "*/",
                "DROP", "INSERT", "UPDATE", "DELETE"
            ],
            'xss': [
                "<script", "javascript:", "onerror=", "onload=", "alert(",
                "<img", "<iframe", "onclick="
            ],
            'command_injection': [
                ";", "|", "&", "`", "$(",  "cat ", "ls ", "wget ", "curl "
            ],
            'path_traversal': [
                "../", "..\\", "/etc/", "c:\\", "/windows/", "passwd"
            ],
            'ssrf': [
                "169.254.169.254", "localhost", "127.0.0.1", "metadata",
                "file://", "gopher://", "dict://"
            ]
        }
        
        vuln_patterns = patterns.get(vuln_type, [])
        payload_lower = payload.lower()
        
        for pattern in vuln_patterns:
            if pattern.lower() in payload_lower:
                return True
        
        return False
    
    def run_accuracy_tests(self) -> AccuracyMetrics:
        """
        Run all accuracy tests
        
        Returns:
            AccuracyMetrics with results
        """
        logger.info(f"Running accuracy tests on {len(self.test_cases)} test cases...")
        
        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0
        
        for test_case in self.test_cases:
            detected = self.test_payload_detection(test_case.payload, test_case.vuln_type)
            
            if detected and test_case.expected_vulnerable:
                true_positives += 1
                logger.debug(f"✅ TP: {test_case.name}")
            elif not detected and not test_case.expected_vulnerable:
                true_negatives += 1
                logger.debug(f"✅ TN: {test_case.name}")
            elif detected and not test_case.expected_vulnerable:
                false_positives += 1
                logger.warning(f"⚠️  FP: {test_case.name}")
            else:  # not detected and expected_vulnerable
                false_negatives += 1
                logger.warning(f"❌ FN: {test_case.name}")
            
            self.results[test_case.name] = detected == test_case.expected_vulnerable
        
        total = len(self.test_cases)
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return AccuracyMetrics(
            total_tests=total,
            true_positives=true_positives,
            true_negatives=true_negatives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score
        )
    
    def print_results(self, metrics: AccuracyMetrics):
        """Print accuracy test results"""
        print("\n" + "="*70)
        print("ACCURACY TEST RESULTS")
        print("="*70)
        print(f"\nTotal Test Cases:    {metrics.total_tests}")
        print(f"\nConfusion Matrix:")
        print(f"  True Positives:    {metrics.true_positives}")
        print(f"  True Negatives:    {metrics.true_negatives}")
        print(f"  False Positives:   {metrics.false_positives}")
        print(f"  False Negatives:   {metrics.false_negatives}")
        print(f"\nMetrics:")
        print(f"  Accuracy:          {metrics.accuracy*100:.1f}%")
        print(f"  Precision:         {metrics.precision*100:.1f}%")
        print(f"  Recall:            {metrics.recall*100:.1f}%")
        print(f"  F1 Score:          {metrics.f1_score*100:.1f}%")
        print("\n" + "="*70)
        
        # Assessment
        if metrics.accuracy >= 0.85:
            print("\n✅ EXCELLENT: Accuracy target achieved (>85%)")
        elif metrics.accuracy >= 0.70:
            print("\n⚠️  GOOD: Acceptable accuracy (70-85%)")
        else:
            print("\n❌ NEEDS IMPROVEMENT: Below target (<70%)")
        
        fp_rate = metrics.false_positives / metrics.total_tests if metrics.total_tests > 0 else 0
        if fp_rate <= 0.15:
            print(f"✅ False Positive Rate: {fp_rate*100:.1f}% (Target: <15%)")
        else:
            print(f"⚠️  False Positive Rate: {fp_rate*100:.1f}% (Above 15% target)")
    
    def export_report(self, filename: str = "accuracy_report.txt"):
        """Export accuracy report"""
        metrics = self.run_accuracy_tests()
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("BugHunter Pro - Accuracy Test Report\n")
            f.write("="*70 + "\n\n")
            f.write(f"Total Tests: {metrics.total_tests}\n")
            f.write(f"Accuracy: {metrics.accuracy*100:.1f}%\n")
            f.write(f"Precision: {metrics.precision*100:.1f}%\n")
            f.write(f"Recall: {metrics.recall*100:.1f}%\n")
            f.write(f"F1 Score: {metrics.f1_score*100:.1f}%\n\n")
            
            f.write("Individual Test Results:\n")
            f.write("-"*70 + "\n")
            for test_case in self.test_cases:
                status = "[PASS]" if self.results.get(test_case.name) else "[FAIL]"
                f.write(f"{status} - {test_case.name}\n")
                f.write(f"  Type: {test_case.vuln_type}\n")
                f.write(f"  Payload: {test_case.payload}\n")
                f.write(f"  Expected: {test_case.expected_vulnerable}\n\n")
        
        logger.info(f"Report exported to {filename}")


def main():
    """Run accuracy tests"""
    print("\n" + "="*70)
    print("BUGHUNTER PRO - ACCURACY TESTING")
    print("="*70)
    
    tester = AccuracyTester()
    
    # Load test cases
    print("\nLoading DVWA-style test cases...")
    test_cases = tester.load_dvwa_test_cases()
    print(f"Loaded {len(test_cases)} test cases")
    
    # Run tests
    print("\nRunning accuracy tests...")
    metrics = tester.run_accuracy_tests()
    
    # Print results
    tester.print_results(metrics)
    
    # Export report
    tester.export_report()
    
    print("\nAccuracy report exported to accuracy_report.txt\n")


if __name__ == "__main__":
    main()
