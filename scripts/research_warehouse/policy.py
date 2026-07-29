"""URL and authority policy shared by registry consumers."""

from __future__ import annotations

from urllib.parse import urlparse

from .errors import RegistryError

RESEARCH_AUTHORITY = "RESEARCH_DATA_CUSTODY_EVIDENCE_ONLY"
FALSE_AUTHORITY_FIELDS = (
    "account_data_authorized",
    "control_authorized",
    "deployment_authorized",
    "dispatch_authorized",
    "execution_authorized",
    "order_authorized",
    "permit_authorized",
    "position_authorized",
    "production_authorized",
    "rpc_authorized",
    "trading_authorized",
)
APPROVED_EXCHANGES = frozenset({"SHFE", "INE"})
APPROVED_MEDIA_TYPES = frozenset(
    {"application/json", "application/octet-stream"}
)


def validate_authority(authority: object) -> dict[str, object]:
    if not isinstance(authority, dict):
        raise RegistryError("authority policy must be an object")
    expected = {"class": RESEARCH_AUTHORITY}
    expected.update({field: False for field in FALSE_AUTHORITY_FIELDS})
    if authority != expected:
        raise RegistryError("registry authority policy is not the frozen Research-only policy")
    return authority


def validate_https_url(
    value: str,
    *,
    allowed_hosts: tuple[str, ...],
    label: str,
    allow_template: bool = False,
) -> str:
    rendered = value
    if allow_template:
        try:
            rendered = value.format(yyyymmdd="20260728")
        except (IndexError, KeyError, ValueError) as exc:
            raise RegistryError(f"{label} contains an unsupported template") from exc
        if value.count("{yyyymmdd}") != 1:
            raise RegistryError(f"{label} must contain exactly one {{yyyymmdd}}")
    parsed = urlparse(rendered)
    if parsed.scheme != "https":
        raise RegistryError(f"{label} must use HTTPS")
    if parsed.username or parsed.password or parsed.fragment:
        raise RegistryError(f"{label} must not contain credentials or a fragment")
    if parsed.port not in (None, 443):
        raise RegistryError(f"{label} must use the default HTTPS port")
    host = (parsed.hostname or "").lower()
    if host not in allowed_hosts:
        raise RegistryError(f"{label} host is not allowlisted: {host}")
    return value


def render_endpoint(template: str, yyyymmdd: str) -> str:
    if len(yyyymmdd) != 8 or not yyyymmdd.isascii() or not yyyymmdd.isdigit():
        raise RegistryError("endpoint date must be an eight-digit YYYYMMDD")
    return template.format(yyyymmdd=yyyymmdd)


def validate_redirect(url: str, allowed_hosts: tuple[str, ...]) -> str:
    """Re-apply the exact source allowlist to every redirect target."""
    return validate_https_url(
        url,
        allowed_hosts=allowed_hosts,
        label="redirect target",
    )
