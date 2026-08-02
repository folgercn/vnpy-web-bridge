from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
import tempfile

import pytest


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
