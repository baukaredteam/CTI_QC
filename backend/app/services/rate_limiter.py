"""Daily counter rate limiter with 429 Retry-After support.

NOT a token bucket — a simple daily counter that resets at midnight UTC.
Obeys upstream 429 Retry-After headers when reported by the caller.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone


class RateLimitExceeded(Exception):
    """Raised when the daily limit is exhausted."""

    def __init__(self, retry_after: float) -> None:
        self.retry_after = retry_after
        super().__init__(
            f"Daily rate limit exceeded. Retry after {retry_after:.0f}s"
        )


class DailyRateLimiter:
    """Daily counter rate limiter.

    Args:
        daily_limit: Maximum calls per UTC day.
    """

    def __init__(self, daily_limit: int = 5000) -> None:
        self.daily_limit = daily_limit
        self._count = 0
        self._current_day: str = ""
        self._retry_after_until: float = 0.0
        self._lock = asyncio.Lock()

    def _today(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _reset_if_new_day(self) -> None:
        today = self._today()
        if today != self._current_day:
            self._current_day = today
            self._count = 0

    def _seconds_until_midnight(self) -> float:
        now = datetime.now(timezone.utc)
        midnight = now.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        # Add one day to get next midnight
        from datetime import timedelta

        next_midnight = midnight + timedelta(days=1)
        return (next_midnight - now).total_seconds()

    async def acquire(self) -> None:
        """Acquire a slot. Raises RateLimitExceeded if exhausted."""
        async with self._lock:
            # Check upstream 429 back-off
            now = time.monotonic()
            if now < self._retry_after_until:
                raise RateLimitExceeded(self._retry_after_until - now)

            self._reset_if_new_day()

            if self._count >= self.daily_limit:
                raise RateLimitExceeded(self._seconds_until_midnight())

            self._count += 1

    async def report_upstream_429(self, retry_after_seconds: float) -> None:
        """Record an upstream 429 Retry-After response.

        Args:
            retry_after_seconds: Seconds to wait before next attempt.
        """
        async with self._lock:
            self._retry_after_until = time.monotonic() + retry_after_seconds

    @property
    def remaining(self) -> int:
        """Remaining calls for the current UTC day."""
        self._reset_if_new_day()
        return max(0, self.daily_limit - self._count)

    @property
    def count(self) -> int:
        """Calls made today."""
        self._reset_if_new_day()
        return self._count
