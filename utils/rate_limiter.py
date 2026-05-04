# utils/rate_limiter.py

import asyncio
import time
from typing import Callable, Any
from collections import deque


class RateLimiter:
    """
    Rate limiter — ek time window mein max requests control karta hai.
    Aggressive scanning se bachne ke liye aur WAF trigger avoid karne ke liye.
    """
    
    def __init__(self, max_requests: int = 10, window: float = 1.0):
        """
        Args:
            max_requests: Window mein max allowed requests
            window: Time window in seconds
        """
        self.max_requests = max_requests
        self.window = window
        self.requests = deque()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Rate limit check karta hai — zaroorat pe wait karta hai."""
        async with self._lock:
            now = time.monotonic()
            
            # Purane requests window se bahar nikalo
            while self.requests and self.requests[0] <= now - self.window:
                self.requests.popleft()
            
            # Agar limit hit ho gayi toh wait karo
            if len(self.requests) >= self.max_requests:
                sleep_time = self.window - (now - self.requests[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                # Purane requests phir se clean karo
                now = time.monotonic()
                while self.requests and self.requests[0] <= now - self.window:
                    self.requests.popleft()
            
            self.requests.append(time.monotonic())
    
    async def __aenter__(self):
        await self.acquire()
        return self
    
    async def __aexit__(self, *args):
        pass


class SyncRateLimiter:
    """
    Sync version — non-async code ke liye.
    """
    
    def __init__(self, max_requests: int = 10, window: float = 1.0):
        self.max_requests = max_requests
        self.window = window
        self.requests = deque()
    
    def acquire(self):
        """Rate limit check karta hai."""
        now = time.monotonic()
        
        while self.requests and self.requests[0] <= now - self.window:
            self.requests.popleft()
        
        if len(self.requests) >= self.max_requests:
            sleep_time = self.window - (now - self.requests[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
            now = time.monotonic()
            while self.requests and self.requests[0] <= now - self.window:
                self.requests.popleft()
        
        self.requests.append(time.monotonic())
    
    def __enter__(self):
        self.acquire()
        return self
    
    def __exit__(self, *args):
        pass


# Preset rate limiters
def get_gentle_limiter() -> RateLimiter:
    """Gentle — 5 requests/sec (WAF wale targets ke liye)"""
    return RateLimiter(max_requests=5, window=1.0)

def get_normal_limiter() -> RateLimiter:
    """Normal — 10 requests/sec"""
    return RateLimiter(max_requests=10, window=1.0)

def get_aggressive_limiter() -> RateLimiter:
    """Aggressive — 20 requests/sec (CTF/lab environments ke liye)"""
    return RateLimiter(max_requests=20, window=1.0)