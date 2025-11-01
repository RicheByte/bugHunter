#!/usr/bin/env python3
"""
BugHunter Pro v7.0 - Feature Demo Script
Demonstrates the newly implemented realistic features
"""

import asyncio
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def demo_config_manager():
    """Demonstrate configuration management"""
    print("\n" + "="*70)
    print("DEMO 1: Configuration Manager")
    print("="*70)
    
    from core.config_manager import ConfigManager, create_default_config
    
    # Create a sample config
    create_default_config("demo_config.yaml")
    
    # Load configuration
    config = ConfigManager("demo_config.yaml")
    config.print_config()
    
    # Validate
    if config.validate():
        print("✅ Configuration is valid!")
    
    # Demonstrate environment override
    import os
    os.environ['BUGHUNTER_THREADS'] = '100'
    config = ConfigManager()
    print(f"\n✅ Threads from ENV: {config.get('threads')}")


def demo_plugin_manager():
    """Demonstrate plugin management"""
    print("\n" + "="*70)
    print("DEMO 2: Plugin Manager")
    print("="*70)
    
    from core.plugin_manager import PluginManager, ExampleXSSPlugin
    
    # Create manager
    manager = PluginManager()
    
    # Register example plugin
    plugin = ExampleXSSPlugin()
    manager.register_plugin(plugin)
    
    # List plugins
    print("\n📦 Registered Plugins:")
    for meta in manager.list_plugins():
        print(f"  ✓ {meta.name} v{meta.version} [{meta.category}] - {meta.description}")
    
    # Execute scan (example)
    print("\n🔍 Executing scan with plugins...")
    results = manager.execute_scan("http://example.com")
    
    for plugin_name, findings in results.items():
        print(f"\n  Plugin: {plugin_name}")
        print(f"  Findings: {len(findings)}")
        for finding in findings[:2]:  # Show first 2
            print(f"    - {finding['type']}: {finding['url']}")


async def demo_async_engine():
    """Demonstrate async HTTP engine"""
    print("\n" + "="*70)
    print("DEMO 3: Async HTTP Engine")
    print("="*70)
    
    from core.async_engine import AsyncScanEngine
    
    # Create test URLs
    test_urls = [
        "http://testphp.vulnweb.com",
        "http://testphp.vulnweb.com/artists.php",
        "http://testphp.vulnweb.com/categories.php",
    ] * 10  # 30 requests
    
    print(f"\n🚀 Scanning {len(test_urls)} URLs asynchronously...")
    
    async with AsyncScanEngine(pool_size=50, rate_limit=100) as engine:
        import time
        start = time.time()
        
        responses = await engine.scan_urls(test_urls)
        
        elapsed = time.time() - start
        
        # Count results
        success = sum(1 for r in responses if r.status == 200)
        errors = sum(1 for r in responses if r.error)
        
        print(f"\n📊 Results:")
        print(f"  Total Requests: {len(test_urls)}")
        print(f"  Successful: {success}")
        print(f"  Errors: {errors}")
        print(f"  Time: {elapsed:.2f}s")
        print(f"  Rate: {len(test_urls)/elapsed:.1f} req/s")
        
        # Get metrics
        metrics = engine.get_performance_metrics()
        print(f"\n📈 Metrics:")
        print(f"  Average Response Time: {metrics['average_response_time']:.3f}s")
        print(f"  Error Rate: {metrics['error_rate']:.1%}")
        print(f"  Status Codes: {metrics['status_codes']}")


def demo_cve_database():
    """Demonstrate CVE database integration"""
    print("\n" + "="*70)
    print("DEMO 4: CVE Database Integration")
    print("="*70)
    
    from modules.cve_database import CVEDatabase
    
    # Initialize database
    print("\n📚 Initializing CVE Database...")
    db = CVEDatabase()
    
    # Fetch a famous CVE (Log4Shell)
    cve_id = "CVE-2021-44228"
    print(f"\n🔍 Fetching {cve_id} (Log4Shell)...")
    
    if db.fetch_and_store_cve(cve_id):
        print(f"✅ Successfully fetched and stored {cve_id}")
        
        # Search for it
        results = db.search_cves(keyword="log4j", limit=5)
        
        if results:
            print(f"\n📋 Found {len(results)} CVE(s) related to 'log4j':")
            for cve in results:
                print(f"\n  CVE: {cve['cve_id']}")
                print(f"  Severity: {cve['cvss_v3_severity']} ({cve['cvss_v3_score']})")
                print(f"  Description: {cve['description'][:100]}...")
    
    # Get database stats
    print("\n📊 Database Statistics:")
    stats = db.get_stats()
    print(f"  Total CVEs: {stats['total_cves']}")
    print(f"  By Severity: {stats['by_severity']}")
    print(f"  With Exploits: {stats['with_exploits']}")
    print(f"  Total Exploits: {stats['total_exploits']}")
    
    print("\n💡 Note: This uses the real NVD API (rate limited to 5 req/30s)")


def main():
    """Run all demos"""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║           BugHunter Pro v7.0 - Realistic Features Demo              ║
║                                                                      ║
║  Demonstrating honestly implemented, functional features            ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Demo 1: Config Manager
        demo_config_manager()
        
        # Demo 2: Plugin Manager
        demo_plugin_manager()
        
        # Demo 3: Async Engine
        print("\n⏳ Running async demo (this will take a moment)...")
        asyncio.run(demo_async_engine())
        
        # Demo 4: CVE Database
        demo_cve_database()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
    
    print("\n" + "="*70)
    print("✅ Demo Complete!")
    print("="*70)
    print("\nNext Steps:")
    print("  1. Check IMPLEMENTATION_STATUS.md for progress")
    print("  2. Review IMPLEMENTATION_PLAN_REALISTIC.md for roadmap")
    print("  3. Install dependencies: pip install -r requirements.txt")
    print("  4. Explore the new modules in core/ and modules/")
    print("\n")


if __name__ == "__main__":
    main()
