import time
from typing import Optional


class CircuitBreakerState:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.total_requests = 0
        self.total_failures = 0
        self.last_success_time: Optional[float] = None

    def _now(self) -> float:
        return time.time()

    def allow_request(self) -> bool:
        self.total_requests += 1
        if self.state == CircuitBreakerState.CLOSED:
            return True

        if self.state == CircuitBreakerState.OPEN:
            if self.last_failure_time and (self._now() - self.last_failure_time) >= self.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                return True
            return False

        return True  # HALF_OPEN allows probe

    def record_success(self):
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED
        self.last_success_time = self._now()

    def record_failure(self):
        self.total_failures += 1
        self.failure_count += 1
        self.last_failure_time = self._now()

        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN

    def reset(self):
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "total_requests": self.total_requests,
            "total_failures": self.total_failures,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
        }


_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(name: str, failure_threshold: int = 3, recovery_timeout: float = 30.0) -> CircuitBreaker:
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name, failure_threshold, recovery_timeout)
    return _breakers[name]


def all_breaker_states() -> list[dict]:
    return [b.to_dict() for b in _breakers.values()]
