#!/usr/bin/env python3
"""
Async HTTP Engine for BugHunter Pro
Provides high-performance async HTTP operations with connection pooling and rate limiting
Target: 500+ requests/second
"""

import asyncio
import aiohttp
import time
import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class AsyncResponse:
    """Wrapper for async HTTP response"""
    url: str
    status: int
    headers: Dict[str, str]
    text: str
    elapsed: float
    error: Optional[str] = None


class AsyncRateLimiter:
    """Token bucket rate limiter for async operations"""
    
    def __init__(self, rate: float = 100.0, burst: int = 200):
        """
        Args:
            rate: Requests per second
            burst: Maximum burst size
        """
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens, waiting if necessary"""
        async with self._lock:
            while self.tokens < tokens:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last_update = now
                
                if self.tokens < tokens:
                    sleep_time = (tokens - self.tokens) / self.rate
                    await asyncio.sleep(sleep_time)
            
            self.tokens -= tokens


class AsyncConnectionPool:
    """Connection pool manager for async HTTP operations"""
    
    def __init__(
        self,
        pool_size: int = 100,
        timeout: int = 30,
        rate_limit: float = 100.0,
        user_agent: Optional[str] = None
    ):
        """
        Args:
            pool_size: Maximum concurrent connections
            timeout: Request timeout in seconds
            rate_limit: Requests per second
            user_agent: Custom user agent string
        """
        self.pool_size = pool_size
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.rate_limiter = AsyncRateLimiter(rate=rate_limit)
        self.user_agent = user_agent or "BugHunter Pro/7.0 (Async Scanner)"
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._stats = {
            'requests': 0,
            'errors': 0,
            'total_time': 0.0,
            'status_codes': defaultdict(int)
        }
    
    async def __aenter__(self):
        """Context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.close()
    
    async def initialize(self):
        """Initialize the connection pool"""
        if self._session is None:
            connector = aiohttp.TCPConnector(
                limit=self.pool_size,
                limit_per_host=20,
                ttl_dns_cache=300,
                enable_cleanup_closed=True
            )
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent}
            )
            
            self._semaphore = asyncio.Semaphore(self.pool_size)
            logger.info(f"✅ Async connection pool initialized (size: {self.pool_size})")
    
    async def close(self):
        """Close the connection pool"""
        if self._session:
            await self._session.close()
            self._session = None
            logger.info("Connection pool closed")
    
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        verify_ssl: bool = False
    ) -> AsyncResponse:
        """
        Perform async GET request
        
        Args:
            url: Target URL
            headers: Custom headers
            params: Query parameters
            allow_redirects: Follow redirects
            verify_ssl: Verify SSL certificates
        
        Returns:
            AsyncResponse object
        """
        return await self._request(
            'GET', url, headers=headers, params=params,
            allow_redirects=allow_redirects, verify_ssl=verify_ssl
        )
    
    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        verify_ssl: bool = False
    ) -> AsyncResponse:
        """
        Perform async POST request
        
        Args:
            url: Target URL
            data: Form data
            json: JSON data
            headers: Custom headers
            allow_redirects: Follow redirects
            verify_ssl: Verify SSL certificates
        
        Returns:
            AsyncResponse object
        """
        return await self._request(
            'POST', url, data=data, json=json, headers=headers,
            allow_redirects=allow_redirects, verify_ssl=verify_ssl
        )
    
    async def _request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> AsyncResponse:
        """Internal request method with rate limiting and error handling"""
        if not self._session:
            await self.initialize()
        
        # Rate limiting
        await self.rate_limiter.acquire()
        
        start_time = time.monotonic()
        
        async with self._semaphore:
            try:
                verify_ssl = kwargs.pop('verify_ssl', False)
                
                async with self._session.request(
                    method,
                    url,
                    ssl=verify_ssl,
                    **kwargs
                ) as response:
                    text = await response.text()
                    elapsed = time.monotonic() - start_time
                    
                    # Update stats
                    self._stats['requests'] += 1
                    self._stats['total_time'] += elapsed
                    self._stats['status_codes'][response.status] += 1
                    
                    return AsyncResponse(
                        url=str(response.url),
                        status=response.status,
                        headers=dict(response.headers),
                        text=text,
                        elapsed=elapsed
                    )
            
            except asyncio.TimeoutError:
                elapsed = time.monotonic() - start_time
                self._stats['errors'] += 1
                logger.warning(f"Timeout for {url}")
                return AsyncResponse(
                    url=url,
                    status=0,
                    headers={},
                    text="",
                    elapsed=elapsed,
                    error="Timeout"
                )
            
            except aiohttp.ClientError as e:
                elapsed = time.monotonic() - start_time
                self._stats['errors'] += 1
                logger.warning(f"Client error for {url}: {e}")
                return AsyncResponse(
                    url=url,
                    status=0,
                    headers={},
                    text="",
                    elapsed=elapsed,
                    error=str(e)
                )
            
            except Exception as e:
                elapsed = time.monotonic() - start_time
                self._stats['errors'] += 1
                logger.error(f"Unexpected error for {url}: {e}")
                return AsyncResponse(
                    url=url,
                    status=0,
                    headers={},
                    text="",
                    elapsed=elapsed,
                    error=str(e)
                )
    
    async def batch_get(
        self,
        urls: List[str],
        headers: Optional[Dict[str, str]] = None,
        show_progress: bool = True
    ) -> List[AsyncResponse]:
        """
        Perform batch GET requests
        
        Args:
            urls: List of URLs to fetch
            headers: Custom headers for all requests
            show_progress: Show progress logging
        
        Returns:
            List of AsyncResponse objects
        """
        if not self._session:
            await self.initialize()
        
        tasks = []
        for url in urls:
            task = self.get(url, headers=headers)
            tasks.append(task)
        
        if show_progress:
            logger.info(f"🚀 Starting batch request for {len(urls)} URLs...")
        
        start_time = time.monotonic()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - start_time
        
        # Handle exceptions in responses
        valid_responses = []
        for i, resp in enumerate(responses):
            if isinstance(resp, Exception):
                logger.error(f"Error fetching {urls[i]}: {resp}")
                valid_responses.append(AsyncResponse(
                    url=urls[i],
                    status=0,
                    headers={},
                    text="",
                    elapsed=0,
                    error=str(resp)
                ))
            else:
                valid_responses.append(resp)
        
        if show_progress:
            rate = len(urls) / elapsed if elapsed > 0 else 0
            logger.info(f"✅ Batch completed: {len(urls)} requests in {elapsed:.2f}s ({rate:.1f} req/s)")
        
        return valid_responses
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        avg_time = self._stats['total_time'] / self._stats['requests'] if self._stats['requests'] > 0 else 0
        
        return {
            'total_requests': self._stats['requests'],
            'total_errors': self._stats['errors'],
            'average_response_time': avg_time,
            'status_codes': dict(self._stats['status_codes']),
            'error_rate': self._stats['errors'] / self._stats['requests'] if self._stats['requests'] > 0 else 0
        }
    
    def reset_stats(self):
        """Reset statistics"""
        self._stats = {
            'requests': 0,
            'errors': 0,
            'total_time': 0.0,
            'status_codes': defaultdict(int)
        }


class AsyncScanEngine:
    """High-level async scanning engine"""
    
    def __init__(
        self,
        pool_size: int = 100,
        timeout: int = 30,
        rate_limit: float = 100.0
    ):
        """
        Args:
            pool_size: Maximum concurrent connections
            timeout: Request timeout
            rate_limit: Requests per second
        """
        self.pool = AsyncConnectionPool(
            pool_size=pool_size,
            timeout=timeout,
            rate_limit=rate_limit
        )
    
    async def __aenter__(self):
        """Context manager entry"""
        await self.pool.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.pool.close()
    
    async def scan_urls(
        self,
        urls: List[str],
        payload_injector: Optional[callable] = None
    ) -> List[AsyncResponse]:
        """
        Scan multiple URLs with optional payload injection
        
        Args:
            urls: List of URLs to scan
            payload_injector: Function to inject payloads into URLs
        
        Returns:
            List of responses
        """
        if payload_injector:
            urls = [payload_injector(url) for url in urls]
        
        return await self.pool.batch_get(urls)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self.pool.get_stats()


# Example usage and benchmarking
async def benchmark_async_engine():
    """Benchmark the async engine"""
    test_urls = [
        "http://testphp.vulnweb.com",
        "http://testphp.vulnweb.com/artists.php",
        "http://testphp.vulnweb.com/categories.php",
    ] * 50  # 150 requests
    
    logger.info("Starting async engine benchmark...")
    
    async with AsyncScanEngine(pool_size=100, rate_limit=200) as engine:
        start = time.monotonic()
        responses = await engine.scan_urls(test_urls)
        elapsed = time.monotonic() - start
        
        success = sum(1 for r in responses if r.status == 200)
        errors = sum(1 for r in responses if r.error)
        
        logger.info(f"""
Benchmark Results:
==================
Total Requests: {len(test_urls)}
Successful: {success}
Errors: {errors}
Time: {elapsed:.2f}s
Rate: {len(test_urls)/elapsed:.1f} req/s
""")
        
        metrics = engine.get_performance_metrics()
        logger.info(f"Metrics: {metrics}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(benchmark_async_engine())
