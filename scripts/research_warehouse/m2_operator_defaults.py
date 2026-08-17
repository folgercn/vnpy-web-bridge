"""Fixed root-managed paths for the production M2 operator stages."""

from pathlib import Path

from .canonical import sha256
from .errors import RegistryError
from .file_integrity import read_regular_strict

LIBEXEC = Path("/usr/local/libexec/vnpyresearch")
RELEASE = LIBEXEC / "release"
DEFAULT_OPERATOR_STATE = LIBEXEC / "operator-state-v1.json"
DEFAULT_CUSTODY_TRANSITION_RECEIPT = LIBEXEC / "custody-transition-v1.json"
DEFAULT_MANIFEST_PRIVATE_KEY = Path(
    "/private/var/root/vnpyresearch-keys/manifest-private.raw"
)
DEFAULT_BACKUP_PRIVATE_KEY = Path(
    "/private/var/root/vnpyresearch-keys/backup-private.raw"
)
DEFAULT_CALENDAR_PRIVATE_KEY = Path(
    "/private/var/root/vnpyresearch-keys/calendar-private.raw"
)
DEFAULT_MANIFEST_PUBLIC_KEY = LIBEXEC / "manifest-public-key.b64"
SOURCE_COMMIT_PATH = RELEASE / "metadata/source-commit-sha"
DEPENDENCY_LOCK_PATH = RELEASE / "metadata/runtime-requirements-v1.txt"
MANIFEST_SIGNER_KEY_ID = "m2-manifest-prod-20260730"
BACKUP_SIGNER_KEY_ID = "m2-backup-prod-20260730"


def release_binding() -> tuple[str, Path, str]:
    commit_raw = read_regular_strict(
        SOURCE_COMMIT_PATH,
        "M2 operator source commit",
        private=False,
    )
    try:
        commit = commit_raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RegistryError("M2 operator source commit is not ASCII") from exc
    if (
        len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
        or commit_raw != f"{commit}\n".encode()
    ):
        raise RegistryError("M2 operator source commit contract mismatch")
    dependency_raw = read_regular_strict(
        DEPENDENCY_LOCK_PATH,
        "M2 operator dependency lock",
        private=False,
    )
    return commit, DEPENDENCY_LOCK_PATH, sha256(dependency_raw)
