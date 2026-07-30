"""Domain errors for Research warehouse policy."""


class RegistryError(RuntimeError):
    """A source registry or authority policy failed closed."""


class RetryableTransportError(RegistryError):
    """A bounded official-source failure that may be retried safely."""

    def __init__(
        self,
        message: str,
        *,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
