from __future__ import annotations

from collections.abc import Iterator
import os
from pathlib import Path
import tempfile

import pytest

_BOOTSTRAP_ENV = "DEPLOYMENT_DRAIN_INITIAL_BOOTSTRAP_ALLOWED"
_PREVIOUS_BOOTSTRAP_ENV = os.environ.get(_BOOTSTRAP_ENV)
# Service singletons are constructed while pytest imports test modules. Permit
# only that isolated test custody bootstrap, then restore the environment
# before any test executes or constructs production Settings.
os.environ[_BOOTSTRAP_ENV] = "true"


def pytest_collection_finish() -> None:
    if _PREVIOUS_BOOTSTRAP_ENV is None:
        os.environ.pop(_BOOTSTRAP_ENV, None)
    else:
        os.environ[_BOOTSTRAP_ENV] = _PREVIOUS_BOOTSTRAP_ENV


@pytest.fixture
def secure_tmp_path() -> Iterator[Path]:
    """Exercise strict custody parent guards outside root-owned sticky /tmp."""

    with tempfile.TemporaryDirectory(
        prefix="cfast-secure-test-",
        dir=Path.home(),
    ) as directory:
        path = Path(directory)
        path.chmod(0o700)
        yield path
