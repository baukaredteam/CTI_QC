"""Async circuit breaker decorator factory.

States: CLOSED (normal) → OPEN (failing) → HALF_OPEN (probe).
Usage:
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)

    @breaker
    async def call_external():
        ...
"""

from __future__ import annotations

import asyncio
import enum
import time
from functools import wraps
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is attempted while the circuit is open."""

    def __init__(self, retry_after: float) -> None:
        self.retry_after = retry_after
        super().__init__(f"Circuit is open. Retry after {retry_after:.1f}s")


class CircuitBreaker:
    """Async decorator factory implementing the circuit breaker pattern.

    Args:
        failure_threshold: Consecutive failures before opening.
        recovery_timeout: Seconds to wait in OPEN before moving to HALF_OPEN.
        half_open_max_calls: Max concurrent probe calls in HALF_OPEN.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 1,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        """Return current state, transitioning OPEN → HALF_OPEN if cooldown elapsed."""
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
        return self._state

    async def _on_success(self) -> None:
        async with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED
            self._half_open_calls = 0

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN

    def __call__(self, func: F) -> F:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            current = self.state
            if current == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                retry_after = max(0.0, self.recovery_timeout - elapsed)
                raise CircuitOpenError(retry_after)

            if current == CircuitState.HALF_OPEN:
                async with self._lock:
                    if self._half_open_calls >= self.half_open_max_calls:
                        raise CircuitOpenError(self.recovery_timeout)
                    self._half_open_calls += 1

            try:
                result = await func(*args, **kwargs)
            except Exception:
                await self._on_failure()
                raise
            else:
                await self._on_success()
                return result

        return wrapper  # type: ignore[return-value]
