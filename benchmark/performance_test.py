#!/usr/bin/env python3
"""
Performance Benchmarking for BugHunter Pro
Tests async engine throughput, latency, and resource usage
"""

import asyncio
import time
import statistics
import psutil
import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Benchmark result container"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_time: float
    requests_per_second: float
    avg_latency: float
    min_latency: float
    max_latency: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    cpu_usage: float
    memory_usage_mb: float


class PerformanceBenchmark:
    """Performance benchmarking tool"""
    
    def __init__(self):
        """Initialize benchmark"""
        self.results: List[BenchmarkResult] = []
    
    async def benchmark_async_engine(
        self,
        num_requests: int = 1000,
        pool_size: int = 100,
        rate_limit: float = 500.0
    ) -> BenchmarkResult:
        """
        Benchmark async engine performance
        
        Args:
            num_requests: Number of requests to make
            pool_size: Connection pool size
            rate_limit: Rate limit (req/s)
        
        Returns:
            BenchmarkResult
        """
        from core.async_engine import AsyncConnectionPool
        
        logger.info(f"Starting benchmark: {num_requests} requests, pool_size={pool_size}, rate_limit={rate_limit}")
        
        # Test URLs (use httpbin.org for testing)
        test_url = "https://httpbin.org/delay/0"
        urls = [test_url] * num_requests
        
        # Track metrics
        latencies = []
        successful = 0
        failed = 0
        
        # Get initial resource usage
        process = psutil.Process()
        cpu_start = process.cpu_percent()
        mem_start = process.memory_info().rss / 1024 / 1024  # MB
        
        start_time = time.time()
        
        try:
            async with AsyncConnectionPool(pool_size=pool_size, rate_limit=rate_limit) as pool:
                # Make requests in batches to avoid overwhelming the system
                batch_size = min(100, pool_size)
                
                for i in range(0, len(urls), batch_size):
                    batch_urls = urls[i:i+batch_size]
                    
                    batch_start = time.time()
                    results = await pool.batch_get(batch_urls)
                    batch_time = time.time() - batch_start
                    
                    # Record latency per request in batch
                    for result in results:
                        if result and result.get('status') in [200, 201, 204]:
                            successful += 1
                            latencies.append(batch_time / len(batch_urls))
                        else:
                            failed += 1
        
        except Exception as e:
            logger.error(f"Benchmark error: {e}")
            failed = num_requests - successful
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Get final resource usage
        cpu_end = process.cpu_percent()
        mem_end = process.memory_info().rss / 1024 / 1024
        
        # Calculate statistics
        if latencies:
            avg_latency = statistics.mean(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            sorted_latencies = sorted(latencies)
            p50_latency = sorted_latencies[int(len(sorted_latencies) * 0.50)]
            p95_latency = sorted_latencies[int(len(sorted_latencies) * 0.95)]
            p99_latency = sorted_latencies[int(len(sorted_latencies) * 0.99)]
        else:
            avg_latency = min_latency = max_latency = 0
            p50_latency = p95_latency = p99_latency = 0
        
        result = BenchmarkResult(
            total_requests=num_requests,
            successful_requests=successful,
            failed_requests=failed,
            total_time=total_time,
            requests_per_second=successful / total_time if total_time > 0 else 0,
            avg_latency=avg_latency,
            min_latency=min_latency,
            max_latency=max_latency,
            p50_latency=p50_latency,
            p95_latency=p95_latency,
            p99_latency=p99_latency,
            cpu_usage=(cpu_start + cpu_end) / 2,
            memory_usage_mb=mem_end - mem_start
        )
        
        self.results.append(result)
        return result
    
    def benchmark_local_performance(self, iterations: int = 10000) -> Dict:
        """
        Benchmark local operations (no network)
        
        Args:
            iterations: Number of iterations
        
        Returns:
            Performance metrics
        """
        from modules.evasion_advanced import AdvancedEvasion
        from modules.payload_generator import PayloadGenerator
        
        logger.info(f"Benchmarking local operations: {iterations} iterations")
        
        results = {
            'evasion_encoding': 0,
            'payload_generation': 0,
            'total_time': 0
        }
        
        # Benchmark evasion encoding
        evasion = AdvancedEvasion()
        payload = "' OR 1=1--"
        
        start = time.time()
        for _ in range(iterations):
            variants = evasion.generate_variants(payload)
        evasion_time = time.time() - start
        results['evasion_encoding'] = iterations / evasion_time
        
        # Benchmark payload generation
        generator = PayloadGenerator()
        
        start = time.time()
        for _ in range(iterations // 10):  # Fewer iterations for payload gen
            payloads = generator.generate_payloads('sql_injection')
        payload_time = time.time() - start
        results['payload_generation'] = (iterations // 10) / payload_time
        
        results['total_time'] = evasion_time + payload_time
        
        return results
    
    def print_results(self, result: BenchmarkResult):
        """Print benchmark results"""
        print("\n" + "="*70)
        print("BENCHMARK RESULTS")
        print("="*70)
        print(f"\nTotal Requests:      {result.total_requests:,}")
        print(f"Successful:          {result.successful_requests:,}")
        print(f"Failed:              {result.failed_requests:,}")
        print(f"Total Time:          {result.total_time:.2f}s")
        print(f"\nThroughput:          {result.requests_per_second:.2f} req/s")
        print(f"\nLatency Statistics:")
        print(f"  Average:           {result.avg_latency*1000:.2f}ms")
        print(f"  Min:               {result.min_latency*1000:.2f}ms")
        print(f"  Max:               {result.max_latency*1000:.2f}ms")
        print(f"  P50 (Median):      {result.p50_latency*1000:.2f}ms")
        print(f"  P95:               {result.p95_latency*1000:.2f}ms")
        print(f"  P99:               {result.p99_latency*1000:.2f}ms")
        print(f"\nResource Usage:")
        print(f"  CPU:               {result.cpu_usage:.1f}%")
        print(f"  Memory Delta:      {result.memory_usage_mb:.1f} MB")
        print("="*70)
        
        # Performance assessment
        if result.requests_per_second >= 500:
            print("\n✅ EXCELLENT: Target performance achieved (500+ req/s)")
        elif result.requests_per_second >= 250:
            print("\n⚠️  GOOD: Acceptable performance (250+ req/s)")
        else:
            print("\n❌ NEEDS IMPROVEMENT: Below target (<250 req/s)")
    
    def export_results(self, filename: str = "benchmark_results.txt"):
        """Export results to file"""
        with open(filename, 'w') as f:
            f.write(f"BugHunter Pro Performance Benchmark\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write("="*70 + "\n\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"Test #{i}\n")
                f.write(f"  Requests: {result.total_requests:,}\n")
                f.write(f"  Throughput: {result.requests_per_second:.2f} req/s\n")
                f.write(f"  Avg Latency: {result.avg_latency*1000:.2f}ms\n")
                f.write(f"  Success Rate: {result.successful_requests/result.total_requests*100:.1f}%\n")
                f.write("\n")
        
        logger.info(f"Results exported to {filename}")


async def main():
    """Run performance benchmarks"""
    print("\n" + "="*70)
    print("BUGHUNTER PRO - PERFORMANCE BENCHMARKING")
    print("="*70)
    
    benchmark = PerformanceBenchmark()
    
    # Test 1: Small batch (fast test)
    print("\nTest 1: Small Batch (100 requests)")
    print("-"*70)
    result1 = await benchmark.benchmark_async_engine(
        num_requests=100,
        pool_size=50,
        rate_limit=100.0
    )
    benchmark.print_results(result1)
    
    # Test 2: Medium batch
    print("\n\nTest 2: Medium Batch (500 requests)")
    print("-"*70)
    result2 = await benchmark.benchmark_async_engine(
        num_requests=500,
        pool_size=100,
        rate_limit=500.0
    )
    benchmark.print_results(result2)
    
    # Test 3: Local operations (no network)
    print("\n\nTest 3: Local Operations Benchmark")
    print("-"*70)
    local_results = benchmark.benchmark_local_performance(iterations=1000)
    print(f"\nEvasion Encoding:    {local_results['evasion_encoding']:.2f} ops/s")
    print(f"Payload Generation:  {local_results['payload_generation']:.2f} ops/s")
    print(f"Total Time:          {local_results['total_time']:.2f}s")
    
    # Export results
    benchmark.export_results()
    
    print("\n" + "="*70)
    print("BENCHMARK COMPLETE")
    print("="*70)
    print("\nNote: Network benchmarks require internet connection.")
    print("For accurate results, run multiple times and take average.")
    print("\n")


if __name__ == "__main__":
    asyncio.run(main())
