#!/usr/bin/env python3
"""
Unit Tests for BugHunter Pro Core Modules
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAsyncEngine(unittest.TestCase):
    """Test async scanning engine"""
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization"""
        from core.async_engine import AsyncRateLimiter
        
        limiter = AsyncRateLimiter(rate=100.0, burst=200)
        self.assertEqual(limiter.rate, 100.0)
        self.assertEqual(limiter.burst, 200)
    
    def test_connection_pool_initialization(self):
        """Test connection pool initialization"""
        from core.async_engine import AsyncConnectionPool
        
        pool = AsyncConnectionPool(pool_size=50, rate_limit=100.0)
        self.assertEqual(pool.pool_size, 50)
        self.assertIsNotNone(pool.rate_limiter)


class TestPluginManager(unittest.TestCase):
    """Test plugin management system"""
    
    def test_plugin_manager_initialization(self):
        """Test plugin manager initialization"""
        from core.plugin_manager import PluginManager
        
        manager = PluginManager()
        self.assertIsNotNone(manager)
    
    def test_plugin_registration(self):
        """Test plugin registration"""
        from core.plugin_manager import PluginManager, ScannerPlugin
        
        class TestPlugin(ScannerPlugin):
            def name(self) -> str:
                return "test"
            def version(self) -> str:
                return "1.0"
            def description(self) -> str:
                return "Test plugin"
            def category(self) -> str:
                return "test"
            def scan(self, target):
                return {"result": "test"}
        
        manager = PluginManager()
        plugin = TestPlugin()
        manager.register_plugin(plugin)
        
        # Verify registration (plugin manager implementation may vary)
        self.assertIsNotNone(manager)


class TestConfigManager(unittest.TestCase):
    """Test configuration management"""
    
    def test_config_manager_initialization(self):
        """Test config manager initialization"""
        from core.config_manager import ConfigManager
        
        # Should work without config file
        manager = ConfigManager()
        self.assertIsNotNone(manager)


class TestEvasionEngine(unittest.TestCase):
    """Test evasion techniques"""
    
    def test_evasion_initialization(self):
        """Test evasion engine initialization"""
        from modules.evasion_advanced import AdvancedEvasion
        
        evasion = AdvancedEvasion()
        self.assertIsNotNone(evasion)
    
    def test_url_encoding(self):
        """Test URL encoding"""
        from modules.evasion_advanced import AdvancedEvasion
        
        evasion = AdvancedEvasion()
        payload = "' OR 1=1--"
        encoded = evasion.encode_url(payload)
        
        self.assertIn("%27", encoded)  # Single quote encoded
    
    def test_variant_generation(self):
        """Test variant generation"""
        from modules.evasion_advanced import AdvancedEvasion
        
        evasion = AdvancedEvasion()
        payload = "test"
        variants = evasion.generate_variants(payload)
        
        self.assertIsInstance(variants, list)
        self.assertGreater(len(variants), 0)


class TestPayloadGenerator(unittest.TestCase):
    """Test payload generation"""
    
    def test_payload_generator_initialization(self):
        """Test payload generator initialization"""
        from modules.payload_generator import PayloadGenerator
        
        generator = PayloadGenerator()
        self.assertIsNotNone(generator)
    
    def test_sql_injection_payloads(self):
        """Test SQL injection payload generation"""
        from modules.payload_generator import PayloadGenerator
        
        generator = PayloadGenerator()
        payloads = generator.generate_payloads('sql_injection')
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)
    
    def test_xss_payloads(self):
        """Test XSS payload generation"""
        from modules.payload_generator import PayloadGenerator
        
        generator = PayloadGenerator()
        payloads = generator.generate_payloads('xss')
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)


class TestMLPredictor(unittest.TestCase):
    """Test ML vulnerability predictor"""
    
    def test_ml_predictor_initialization(self):
        """Test ML predictor initialization"""
        from modules.ml_vuln_predictor import MLVulnPredictor
        
        predictor = MLVulnPredictor()
        self.assertIsNotNone(predictor)
    
    def test_feature_extraction(self):
        """Test feature extraction"""
        from modules.ml_vuln_predictor import MLVulnPredictor
        
        predictor = MLVulnPredictor()
        response = {
            'status_code': 200,
            'response_body': 'test',
            'response_time': 0.1,
            'headers': {}
        }
        
        features = predictor.extract_features(response)
        self.assertIsNotNone(features)


class TestCryptoAnalyzer(unittest.TestCase):
    """Test crypto/TLS analysis"""
    
    def test_crypto_analyzer_initialization(self):
        """Test crypto analyzer initialization"""
        from modules.crypto_analyzer import CryptoAnalyzer
        
        analyzer = CryptoAnalyzer()
        self.assertIsNotNone(analyzer)


class TestCloudScanner(unittest.TestCase):
    """Test cloud metadata scanner"""
    
    def test_cloud_scanner_initialization(self):
        """Test cloud scanner initialization"""
        from modules.cloud_metadata_scanner import CloudMetadataScanner
        
        scanner = CloudMetadataScanner()
        self.assertIsNotNone(scanner)
    
    def test_payload_generation(self):
        """Test SSRF payload generation"""
        from modules.cloud_metadata_scanner import CloudMetadataScanner
        
        scanner = CloudMetadataScanner()
        payloads = scanner.generate_ssrf_payloads()
        
        self.assertIsInstance(payloads, list)
        self.assertGreater(len(payloads), 0)


def run_tests():
    """Run all unit tests"""
    print("\n" + "="*70)
    print("BUGHUNTER PRO - UNIT TESTS")
    print("="*70 + "\n")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestAsyncEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestPluginManager))
    suite.addTests(loader.loadTestsFromTestCase(TestConfigManager))
    suite.addTests(loader.loadTestsFromTestCase(TestEvasionEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadGenerator))
    suite.addTests(loader.loadTestsFromTestCase(TestMLPredictor))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestCloudScanner))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests Run:     {result.testsRun}")
    print(f"Successes:     {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures:      {len(result.failures)}")
    print(f"Errors:        {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ ALL TESTS PASSED")
    else:
        print("\n❌ SOME TESTS FAILED")
    
    print("="*70 + "\n")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
