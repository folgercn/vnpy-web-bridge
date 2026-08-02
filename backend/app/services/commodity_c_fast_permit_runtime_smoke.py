from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.services.commodity_c_fast_research_acceptance_evidence import (
    CommodityCFastResearchAcceptanceEvidenceService,
)

RUNTIME_MODULE_NAMES = (
    "commodity_c_fast_t1_one_shot.py",
    "commodity_c_fast_simnow_research_bundle.py",
    "commodity_c_fast_simnow_research_acceptance.py",
)
OFFLINE_OPERATOR_TOOL_NAMES = (
    "commodity_c_fast_fee_statement_verify.py",
)
RUNTIME_SCHEMA_NAMES = (
    "commodity-c-fast-simnow-research-bundle-v1.schema.json",
    "commodity-c-fast-simnow-research-bundle-trusted-keys-v1.schema.json",
    "commodity-c-fast-simnow-research-bundle-install-receipt-v1.schema.json",
    "commodity-c-fast-simnow-research-acceptance-v1.schema.json",
    "commodity-c-fast-simnow-research-acceptance-trusted-keys-v1.schema.json",
    "commodity-c-fast-simnow-research-acceptance-consume-v1.schema.json",
    "commodity-c-fast-simnow-research-acceptance-receipt-v1.schema.json",
    "commodity-c-fast-t1-query-terminal-v6.schema.json",
    "commodity-c-fast-questdb-readonly-proof-v1.schema.json",
    "commodity-c-fast-l1-l5-audit-v1.schema.json",
    "commodity-c-fast-l1-l5-audit-v2.schema.json",
    "commodity-c-fast-l1-l5-audit-manifest-v2.schema.json",
)
FORBIDDEN_SIGNER_NAMES = (
    "commodity_c_fast_simnow_sign_research_bundle.py",
    "commodity_c_fast_simnow_sign_research_acceptance.py",
    "commodity_c_fast_simnow_sign_execution_permit.py",
    "commodity_c_fast_execution_quality_sign_runtime_artifact.py",
)


class CommodityCFastPermitRuntimePackagingError(RuntimeError):
    """The production image lacks the exact fail-closed permit verifier closure."""


def _require_regular(path: Path, label: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise CommodityCFastPermitRuntimePackagingError(
            f"{label} is not a regular non-symlink file"
        )


def validate_runtime_packaging(
    *, require_signers_absent: bool = False
) -> dict[str, Any]:
    import commodity_c_fast_simnow_research_acceptance as acceptance
    import commodity_c_fast_simnow_research_bundle as bundle
    import commodity_c_fast_t1_one_shot as one_shot

    modules = (one_shot, bundle, acceptance)
    scripts_root = Path(one_shot.__file__).resolve().parent
    runtime_root = scripts_root.parent
    expected_module_paths = tuple(
        scripts_root / name for name in RUNTIME_MODULE_NAMES
    )
    observed_module_paths = tuple(
        Path(module.__file__).resolve() for module in modules
    )
    if observed_module_paths != expected_module_paths:
        raise CommodityCFastPermitRuntimePackagingError(
            "runtime verifier module closure/path mismatch"
        )
    for path in expected_module_paths:
        _require_regular(path, f"runtime verifier {path.name}")
    operator_tool_paths = tuple(
        scripts_root / name for name in OFFLINE_OPERATOR_TOOL_NAMES
    )
    for path in operator_tool_paths:
        _require_regular(path, f"offline operator tool {path.name}")
    signer_paths = tuple(scripts_root / name for name in FORBIDDEN_SIGNER_NAMES)
    if require_signers_absent:
        packaged_python_names = tuple(
            sorted(path.name for path in scripts_root.glob("*.py"))
        )
        expected_python_names = tuple(
            sorted((*RUNTIME_MODULE_NAMES, *OFFLINE_OPERATOR_TOOL_NAMES))
        )
        if packaged_python_names != expected_python_names:
            raise CommodityCFastPermitRuntimePackagingError(
                "runtime image contains code outside the exact verifier closure"
            )
        for path in signer_paths:
            if not path.exists():
                continue
            raise CommodityCFastPermitRuntimePackagingError(
                f"signer must not be packaged in runtime image: {path.name}"
            )

    schema_root = runtime_root / "docs" / "schemas"
    expected_schema_paths = tuple(
        schema_root / name for name in RUNTIME_SCHEMA_NAMES
    )
    module_schema_paths = (
        bundle.BUNDLE_SCHEMA_PATH,
        bundle.KEYRING_SCHEMA_PATH,
        bundle.RECEIPT_SCHEMA_PATH,
        acceptance.ACCEPTANCE_SCHEMA_PATH,
        acceptance.KEYRING_SCHEMA_PATH,
        acceptance.CONSUME_SCHEMA_PATH,
        acceptance.RECEIPT_SCHEMA_PATH,
    )
    if tuple(path.resolve() for path in module_schema_paths) != tuple(
        path.resolve() for path in expected_schema_paths[: len(module_schema_paths)]
    ):
        raise CommodityCFastPermitRuntimePackagingError(
            "runtime verifier schema closure/path mismatch"
        )
    for path in expected_schema_paths:
        _require_regular(path, f"runtime schema {path.name}")
    if require_signers_absent:
        packaged_schema_names = tuple(
            sorted(path.name for path in schema_root.glob("*.schema.json"))
        )
        if packaged_schema_names != tuple(sorted(RUNTIME_SCHEMA_NAMES)):
            raise CommodityCFastPermitRuntimePackagingError(
                "runtime image contains schemas outside the exact verifier closure"
            )

    authority_flag_names = (
        "commodity_c_fast_simnow_shakedown_enabled",
        "commodity_c_fast_simnow_auto_dispatch_enabled",
        "commodity_c_fast_simnow_execution_permit_enabled",
    )
    if any(
        Settings.model_fields[name].default is not False
        for name in authority_flag_names
    ):
        raise CommodityCFastPermitRuntimePackagingError(
            "C_FAST SimNow runtime switches must remain disabled by default"
        )
    settings = Settings(
        _env_file=None,
        app_env="development",
        **{name: False for name in authority_flag_names},
    )
    evidence = CommodityCFastResearchAcceptanceEvidenceService(
        settings=settings
    )
    evidence.bind_full_acceptance_verifier(
        acceptance.verify_signed_acceptance,
        contract_schema_validator=acceptance.validate_json_schema,
        consume_schema_path=acceptance.CONSUME_SCHEMA_PATH,
        receipt_schema_path=acceptance.RECEIPT_SCHEMA_PATH,
    )
    if (
        evidence._full_acceptance_verifier
        is not acceptance.verify_signed_acceptance
        or evidence._contract_schema_validator
        is not acceptance.validate_json_schema
        or evidence._consume_schema_path != acceptance.CONSUME_SCHEMA_PATH
        or evidence._receipt_schema_path != acceptance.RECEIPT_SCHEMA_PATH
    ):
        raise CommodityCFastPermitRuntimePackagingError(
            "full #165 verifier binding smoke failed"
        )
    return {
        "status": "C_FAST_SIMNOW_PERMIT_RUNTIME_PACKAGED_DEFAULT_OFF",
        "runtime_modules": list(RUNTIME_MODULE_NAMES),
        "runtime_schemas": list(RUNTIME_SCHEMA_NAMES),
        "offline_operator_tools": list(OFFLINE_OPERATOR_TOOL_NAMES),
        "signers_packaged": any(path.exists() for path in signer_paths),
        "shakedown_enabled": False,
        "auto_dispatch_enabled": False,
        "execution_permit_enabled": False,
        "orders_sent": 0,
        "positions_modified": 0,
        "production_allowed": False,
    }


def main() -> int:
    print(
        json.dumps(
            validate_runtime_packaging(require_signers_absent=True),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
