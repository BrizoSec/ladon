"""Circuit breaker pattern for resilient service communication.

Based on LADON architecture patterns from CLAUDE.md.
"""

import logging
from datetime import datetime, timezone
from typing import Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitBreaker:
    """Circuit breaker for preventing cascading failures.

    Implements the circuit breaker pattern with three states:
    - closed: Normal operation, requests pass through
    - open: Failures exceeded threshold, requests fail fast
    - half_open: Testing if service recovered, single request allowed

    Based on ladon-common circuit breaker pattern from CLAUDE.md.
    Supports async operations for use with aiohttp and other async libraries.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        timeout_seconds: int = 60,
    ):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            timeout_seconds: Seconds to wait before attempting half-open
        """
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.state = "closed"  # closed, open, half_open

    async def call(self, func: Callable) -> T:
        """Execute async function with circuit breaker protection.

        Args:
            func: Async function to execute

        Returns:
            Result from the function

        Raises:
            RuntimeError: If circuit is open
            Exception: Any exception raised by the function
        """
        if self.state == "open":
            # Check if timeout has passed
            if self.last_failure_time:
                elapsed = (datetime.now(timezone.utc) - self.last_failure_time).total_seconds()
                if elapsed >= self.timeout_seconds:
                    self.state = "half_open"
                    self.failure_count = 0  # Reset count when entering half-open
                    logger.info("Circuit breaker entering half-open state")
                else:
                    raise RuntimeError(
                        f"Circuit breaker is OPEN - Service unavailable "
                        f"(retry in {self.timeout_seconds - elapsed:.0f}s)"
                    )

        try:
            result = await func()

            # Success - reset or close circuit
            if self.state == "half_open":
                self.state = "closed"
                self.failure_count = 0
                logger.info("Circuit breaker closed - Service recovered")

            return result

        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now(timezone.utc)

            # Handle state transitions on failure
            if self.state == "half_open":
                # Failure in half-open state immediately reopens circuit
                self.state = "open"
                logger.error(
                    "Circuit breaker REOPENED - Service still unavailable",
                    extra={
                        "failure_count": self.failure_count,
                        "error_type": type(e).__name__,
                        "previous_state": "half_open",
                    },
                )
            elif self.failure_count >= self.failure_threshold and self.state == "closed":
                # Open circuit if threshold reached
                self.state = "open"
                logger.error(
                    "Circuit breaker OPENED - Service unavailable",
                    extra={
                        "failure_count": self.failure_count,
                        "error_type": type(e).__name__,
                    },
                )

            raise
