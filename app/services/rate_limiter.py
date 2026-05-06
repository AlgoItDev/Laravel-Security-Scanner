"""
Rate limiting utilities for controlling request rates.
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional, Callable, Any


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rates.
    
    Args:
        rate: Number of requests allowed per second
        burst: Maximum burst size (token bucket capacity)
    """
    
    def __init__(self, rate: float = 10.0, burst: int = 10) -> None:
        self._rate = rate  # requests per second
        self._burst = burst  # max tokens
        self._tokens = float(burst)  # current tokens
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> None:
        """
        Acquire tokens for making a request.
        Blocks until enough tokens are available.
        """
        async with self._lock:
            while self._tokens < tokens:
                # Refill tokens based on elapsed time
                now = time.monotonic()
                elapsed = now - self._last_refill
                refill = elapsed * self._rate
                if refill > 0:
                    self._tokens = min(self._burst, self._tokens + refill)
                    self._last_refill = now
                
                if self._tokens >= tokens:
                    break
                
                # Calculate sleep time
                sleep_time = (tokens - self._tokens) / self._rate
                # Release lock while sleeping
                self._lock.release()
                try:
                    await asyncio.sleep(sleep_time)
                finally:
                    await self._lock.acquire()
            
            self._tokens -= tokens


class RetryableClient:
    """
    Wrapper around httpx.AsyncClient that adds rate limiting and retry support.
    """
    
    def __init__(
        self,
        client: httpx.AsyncClient,
        rate_limiter: Optional[RateLimiter] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        max_retry_delay: float = 10.0,
    ) -> None:
        self._client = client
        self._limiter = rate_limiter or RateLimiter()
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._max_retry_delay = max_retry_delay
    
    async def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """
        Make an HTTP request with retry logic.
        """
        last_exception = None
        
        for attempt in range(self._max_retries + 1):
            try:
                await self._limiter.acquire()
                
                # Get the method from client (get, post, etc.)
                request_method = getattr(self._client, method.lower())
                resp = await request_method(url, **kwargs)
                return resp
                
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_exception = exc
                
                if attempt < self._max_retries:
                    # Calculate delay with exponential backoff
                    delay = min(
                        self._retry_delay * (2 ** attempt),
                        self._max_retry_delay
                    )
                    await asyncio.sleep(delay)
                else:
                    raise
        
        # This should never be reached due to the raise in the loop
        raise last_exception  # type: ignore
    
    async def get(self, *args, **kwargs) -> httpx.Response:
        # Extract url from args or kwargs
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.get(*args, **kwargs)
        
        return await self._request_with_retry("get", url, **kwargs)
    
    async def post(self, *args, **kwargs) -> httpx.Response:
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.post(*args, **kwargs)
        
        return await self._request_with_retry("post", url, **kwargs)
    
    # Add other HTTP methods as needed
    async def put(self, *args, **kwargs) -> httpx.Response:
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.put(*args, **kwargs)
        
        return await self._request_with_retry("put", url, **kwargs)
    
    async def delete(self, *args, **kwargs) -> httpx.Response:
        if 'url' in kwargs:
            url = kwargs['url']
        elif len(args) > 0:
            url = args[0]
        else:
            return await self._client.delete(*args, **kwargs)
        
        return await self._request_with_retry("delete", url, **kwargs)
    
    # Context manager support
    async def __aenter__(self):
        await self._client.__aenter__()
        return self
    
    async def __aexit__(self, *args):
        return await self._client.__aexit__(*args)
    
    # Proxy attribute access
    def __getattr__(self, name):
        return getattr(self._client, name)
