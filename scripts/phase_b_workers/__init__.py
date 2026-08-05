"""Small, dependency-free Phase B worker runtimes.

The package intentionally does not import the application package.  Each worker
can therefore be copied into a minimal image and started without booting the
web application or any of its process-local services.
"""

CONTRACT_VERSION = "phase_b_worker_contract_v1"
WORKER_PACKAGE_VERSION = "0.1.0"

__all__ = ["CONTRACT_VERSION", "WORKER_PACKAGE_VERSION"]
