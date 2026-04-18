"""Security utilities: rate limiting."""

from __future__ import annotations

import os
import time
import logging
from collections import OrderedDict
from fastapi import HTTPException, Request

logger = logging.getLogger("tee-judge")

# --- Rate Limiting (with bounded memory) ---

RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = int(os.environ.get("TEE_JUDGE_RATE_LIMIT", "30"))
MAX_TRACKED_IPS = 10000  # prevent memory exhaustion


class RateLimiter:
    def __init__(self):
        self._log: OrderedDict[str, list[float]] = OrderedDict()

    def check(self, client_ip: str):
        now = time.time()
        cutoff = now - RATE_LIMIT_WINDOW

        # Evict oldest IPs if over limit
        while len(self._log) > MAX_TRACKED_IPS:
            self._log.popitem(last=False)

        # Clean old entries for this IP
        if client_ip in self._log:
            self._log[client_ip] = [t for t in self._log[client_ip] if t > cutoff]
            if not self._log[client_ip]:
                del self._log[client_ip]

        entries = self._log.get(client_ip, [])
        if len(entries) >= RATE_LIMIT_MAX:
            raise HTTPException(
                429,
                f"Rate limit exceeded. Max {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s.",
            )

        if client_ip not in self._log:
            self._log[client_ip] = []
        self._log[client_ip].append(now)


_limiter = RateLimiter()


def rate_limit(request: Request):
    """Dependency: per-IP rate limiting with bounded memory."""
    client_ip = request.client.host if request.client else "unknown"
    _limiter.check(client_ip)
