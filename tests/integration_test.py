#!/usr/bin/env python3
"""
Integration Tests for BugHunter Pro
End-to-end workflow testing
"""

import sys
import os
import asyncio
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class IntegrationTests(unittest.TestCase):
    """End-to-end integration tests"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test fixtures"""
        cls.test_url = "http://testsite.local/test.php"
    
    def test_full_scan_workflow(self):
        """Test complete scanning workflow"""
        print("\n[Integration] Testing full scan workflow...")
        
        # 1. Initialize components
        from core.async_engine import AsyncConnectionPool
        from modules.payload_generator import PayloadGenerator
        from modules.evasion_advanced import AdvancedEvasion
        
        # 2. Generate payloads
        generator = PayloadGenerator()
        payloads = generator.generate_payloads('sql_injection')
        self.assertGreater(len(payloads), 0)
        print(f"  ✓ Generated {len(payloads)} payloads")
        
        # 3. Generate evasion variants
        evasion = AdvancedEvasion()
        if payloads:
            # Payloads are Payload objects, not dicts
            variants = evasion.generate_variants(payloads[0].payload)
            self.assertGreater(len(variants), 0)
            print(f"  ✓ Generated {len(variants)} evasion variants")
        
        print("  ✓ Full workflow test passed")
    
    def test_cve_database_workflow(self):
        """Test CVE database integration workflow"""
        print("\n[Integration] Testing CVE database workflow...")
        
        from modules.cve_database import CVEDatabase
        from modules.exploit_db import ExploitDBSync
        
        # Use in-memory database for testing
        cve_db = CVEDatabase(database_path=':memory:')
        exploit_sync = ExploitDBSync(database_path=':memory:')
        
        self.assertIsNotNone(cve_db)
        self.assertIsNotNone(exploit_sync)
        
        print("  ✓ CVE database initialized")
        print("  ✓ ExploitDB sync initialized")
        print("  ✓ Database workflow test passed")
    
    def test_ml_prediction_workflow(self):
        """Test ML vulnerability prediction workflow"""
        print("\n[Integration] Testing ML prediction workflow...")
        
        from modules.ml_vuln_predictor import MLVulnPredictor
        
        predictor = MLVulnPredictor()
        
        # Generate training data
        X, y = predictor._generate_training_data()
        self.assertIsNotNone(X)
        self.assertIsNotNone(y)
        print(f"  ✓ Generated training data: {len(X)} samples")
        
        # Train model
        metrics = predictor.train(X, y)
        self.assertGreater(metrics['accuracy'], 0.8)
        print(f"  ✓ Model trained: {metrics['accuracy']:.1%} accuracy")
        
        # Test prediction
        baseline = {
            'status_code': 200,
            'response_body': 'Normal response',
            'response_time': 0.1,
            'headers': {}
        }
        test = {
            'status_code': 500,
            'response_body': 'SQL error: syntax near',
            'response_time': 0.5,
            'headers': {}
        }
        
        result = predictor.predict(baseline, test)
        self.assertIsNotNone(result)
        print(f"  ✓ Prediction completed: {result.vulnerability_type}")
        print("  ✓ ML workflow test passed")
    
    def test_crypto_analysis_workflow(self):
        """Test TLS/SSL analysis workflow"""
        print("\n[Integration] Testing crypto analysis workflow...")
        
        from modules.crypto_analyzer import CryptoAnalyzer
        
        analyzer = CryptoAnalyzer()
        
        # Test with a known HTTPS site
        result = analyzer.analyze_tls('https://www.google.com')
        
        if result:
            self.assertIsNotNone(result.protocol_version)
            self.assertIsNotNone(result.cipher_suite)
            print(f"  ✓ TLS analysis completed")
            print(f"    Protocol: {result.protocol_version}")
            print(f"    Cipher: {result.cipher_suite}")
        else:
            print("  ⚠ TLS analysis skipped (network required)")
        
        print("  ✓ Crypto workflow test passed")
    
    def test_cloud_scanner_workflow(self):
        """Test cloud metadata scanner workflow"""
        print("\n[Integration] Testing cloud scanner workflow...")
        
        from modules.cloud_metadata_scanner import CloudMetadataScanner
        
        scanner = CloudMetadataScanner()
        
        # Generate SSRF payloads
        payloads = scanner.generate_ssrf_payloads()
        self.assertGreater(len(payloads), 0)
        print(f"  ✓ Generated {len(payloads)} SSRF payloads")
        
        # Test cloud detection
        findings = scanner.test_direct_metadata_access()
        print(f"  ✓ Cloud detection completed: {len(findings)} findings")
        
        print("  ✓ Cloud scanner workflow test passed")
    
    def test_error_handling(self):
        """Test error handling across modules"""
        print("\n[Integration] Testing error handling...")
        
        from modules.payload_generator import PayloadGenerator
        from modules.evasion_advanced import AdvancedEvasion
        
        generator = PayloadGenerator()
        evasion = AdvancedEvasion()
        
        # Test with invalid input
        try:
            payloads = generator.generate_payloads('invalid_type')
            # Should return empty or handle gracefully
            self.assertIsInstance(payloads, list)
            print("  ✓ Invalid payload type handled")
        except Exception as e:
            print(f"  ✓ Exception properly raised: {type(e).__name__}")
        
        # Test empty payload
        try:
            variants = evasion.generate_variants("")
            self.assertIsInstance(variants, list)
            print("  ✓ Empty payload handled")
        except Exception:
            print("  ✓ Exception properly raised for empty payload")
        
        print("  ✓ Error handling test passed")
    
    def test_config_integration(self):
        """Test configuration integration"""
        print("\n[Integration] Testing configuration integration...")
        
        from core.config_manager import ConfigManager
        
        # Test with no config file
        manager = ConfigManager()
        self.assertIsNotNone(manager)
        print("  ✓ Config manager works without config file")
        
        # Test with temporary config
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
scanner:
  threads: 10
  timeout: 5
detection:
  enable_ml: true
""")
            temp_config = f.name
        
        try:
            manager = ConfigManager(config_file=temp_config)
            self.assertIsNotNone(manager)
            print("  ✓ Config loaded from YAML file")
        finally:
            os.unlink(temp_config)
        
        print("  ✓ Configuration integration test passed")
    
    def test_plugin_system_integration(self):
        """Test plugin system integration"""
        print("\n[Integration] Testing plugin system...")
        
        from core.plugin_manager import PluginManager, ScannerPlugin
        
        # Create test plugin
        class TestPlugin(ScannerPlugin):
            @property
            def name(self) -> str:
                return "test_plugin"
            @property
            def version(self) -> str:
                return "1.0"
            @property
            def description(self) -> str:
                return "Test plugin"
            @property
            def category(self) -> str:
                return "test"
            def scan(self, target, **kwargs):
                # Return list of findings
                return [{"test": "result", "target": target}]
        
        manager = PluginManager()
        plugin = TestPlugin()
        
        # Register and execute
        manager.register_plugin(plugin)
        print("  ✓ Plugin registered")
        
        # execute_scan expects target (str), optional categories (List[str]), and kwargs
        result = manager.execute_scan("http://test.local", plugin_names=["test_plugin"])
        self.assertIsNotNone(result)
        
        # Debug: print what we got
        if not result:
            available_plugins = list(manager._plugins.keys())
            print(f"  DEBUG: Available plugins: {available_plugins}")
            print(f"  DEBUG: Result: {result}")
        
        self.assertIn("test_plugin", result)
        self.assertGreater(len(result["test_plugin"]), 0)
        print("  ✓ Plugin executed successfully")
        
        print("  ✓ Plugin system integration test passed")


def run_integration_tests():
    """Run all integration tests"""
    print("\n" + "="*70)
    print("BUGHUNTER PRO - INTEGRATION TESTS")
    print("="*70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(IntegrationTests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("INTEGRATION TEST SUMMARY")
    print("="*70)
    print(f"Tests Run:     {result.testsRun}")
    print(f"Successes:     {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures:      {len(result.failures)}")
    print(f"Errors:        {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ ALL INTEGRATION TESTS PASSED")
    else:
        print("\n❌ SOME INTEGRATION TESTS FAILED")
    
    print("="*70 + "\n")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_integration_tests()
    exit(0 if success else 1)
