from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import ValidationError
from referencing import Registry, Resource

from app.core.config import Settings, get_settings
from app.schemas.commodity_c_fast_execution_quality_production_artifacts import (
    CFastExecutionQualityCollectionAdmissionV2DTO,
    CFastExecutionQualityP0AcceptanceV6DTO,
    CFastExecutionQualityRoleTrustedKeysDTO,
    CFastExecutionQualitySignedContractSpecSetDTO,
    CFastExecutionQualitySignedCustodyBindingDTO,
    CFastExecutionQualitySignedPlanDTO,
)
from app.schemas.commodity_c_fast_execution_quality_runtime import (
    ArtifactRole,
    CFastExecutionQualityArtifactVerificationDTO,
)
from app.schemas.commodity_c_fast_shadow import CommodityCFastShadowDTO
from app.services.commodity_c_fast_execution_policy import (
    parse_execution_policy_freeze_json,
    parse_execution_policy_freeze_v2_json,
    verify_execution_policy_freeze_v2_raw_chain,
)
from app.services.commodity_c_fast_execution_quality import (
    reload_and_verify_virtual_intent_plan,
)
from app.services.commodity_c_fast_execution_quality_artifact_revalidation import (
    ARTIFACT_ROLES,
    ArtifactVerificationRequest,
    SignedArtifactVerification,
)
from app.services.commodity_c_fast_execution_quality_runtime_admission import (
    _read_exact_private_canonical_json,
    canonical_json,
    sha256_bytes,
)
from app.services.commodity_c_fast_shadow import (
    C_FAST_PRODUCT_SPECS_V1,
    PRODUCTS,
    CommodityCFastShadowService,
)


ROLE_SIGNER_PURPOSES: dict[ArtifactRole, str] = {
    "signed_p0_acceptance": ("c_fast_execution_quality_query_v6_p0_acceptance_signer"),
    "collection_admission": (
        "c_fast_execution_quality_query_v6_collection_admission_signer"
    ),
    "execution_policy": "execution_quality_policy_freeze_signer",
    "signed_snapshot": "research_snapshot_signer",
    "virtual_intent_plan": "c_fast_execution_quality_virtual_plan_signer",
    "contract_spec_set": "c_fast_execution_quality_contract_spec_signer",
    "custody_binding": "c_fast_execution_quality_custody_binding_signer",
}
_FALSE_AUTHORITY = {
    "collection_authorized": False,
    "runtime_activation_authorized": False,
    "authority_granted": False,
    "dispatch_allowed": False,
    "order_authorized": False,
    "position_mutation_authorized": False,
    "database_mutation_authorized": False,
    "deployment_mutation_authorized": False,
    "replacement_allowed": False,
    "production_allowed": False,
}
_BINDINGS: dict[ArtifactRole, tuple[ArtifactRole, ...]] = {
    "signed_p0_acceptance": (),
    "collection_admission": ("signed_p0_acceptance", "execution_policy"),
    "execution_policy": (),
    "signed_snapshot": ("contract_spec_set",),
    "virtual_intent_plan": (
        "execution_policy",
        "signed_snapshot",
        "contract_spec_set",
    ),
    "contract_spec_set": (),
    "custody_binding": tuple(ARTIFACT_ROLES[:-1]),
}
_ROOT = Path(__file__).resolve().parents[3]
_TERMINAL_SCHEMA = (
    _ROOT / "docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json"
)
_READONLY_PROOF_SCHEMA = (
    _ROOT / "docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json"
)
_AUDIT_SCHEMA = _ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json"
_AUDIT_V1_SCHEMA = _ROOT / "docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json"
_AUDIT_V1_RESOURCE_URI = "urn:vnpy-web-bridge:schema:commodity-c-fast-l1-l5-audit-v1"
CUSTOM_SIGNATURE_DOMAIN = b"commodity_c_fast_execution_quality_role_signature_v1"


def runtime_artifact_signature_message(
    role: ArtifactRole,
    unsigned: object,
) -> bytes:
    return (
        CUSTOM_SIGNATURE_DOMAIN
        + b"\0"
        + role.encode("ascii")
        + b"\0"
        + canonical_json(unsigned)
    )


class CFastExecutionQualityProductionVerifierError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CommodityCFastExecutionQualityProductionArtifactVerifier:
    """Replay one exact seven-role production generation.

    The adapter deliberately composes existing semantic verifiers instead of
    accepting a hash-only receipt: policy ancestry is replayed, the signed
    snapshot is checked by the Shadow verifier against the signed spec set,
    and the plan is freshly recompiled from that snapshot and policy.  New
    query-v6 P0/admission/spec/custody envelopes have independent Ed25519
    domains and contain no collection, database, RPC or trading authority.
    """

    def __init__(self, *, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def __call__(
        self,
        requests: Mapping[ArtifactRole, ArtifactVerificationRequest],
    ) -> Mapping[ArtifactRole, SignedArtifactVerification]:
        if set(requests) != set(ARTIFACT_ROLES):
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_ARTIFACT_REQUEST_SET_INCOMPLETE"
            )
        observed = {request.observed_at_utc for request in requests.values()}
        if len(observed) != 1:
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_ARTIFACT_OBSERVATION_SPLICE"
            )
        observed_at = observed.pop()
        keyrings, domains = self._load_keyrings()
        self._require_disjoint_domains(domains)

        try:
            custody = CFastExecutionQualitySignedCustodyBindingDTO.model_validate(
                requests["custody_binding"].payload
            )
            p0 = CFastExecutionQualityP0AcceptanceV6DTO.model_validate(
                requests["signed_p0_acceptance"].payload
            )
            admission = CFastExecutionQualityCollectionAdmissionV2DTO.model_validate(
                requests["collection_admission"].payload
            )
            signed_plan = CFastExecutionQualitySignedPlanDTO.model_validate(
                requests["virtual_intent_plan"].payload
            )
            signed_specs = CFastExecutionQualitySignedContractSpecSetDTO.model_validate(
                requests["contract_spec_set"].payload
            )
        except ValidationError as exc:
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_SIGNED_ARTIFACT_SCHEMA_INVALID"
            ) from exc

        custom_models = {
            "signed_p0_acceptance": p0,
            "collection_admission": admission,
            "virtual_intent_plan": signed_plan,
            "contract_spec_set": signed_specs,
            "custody_binding": custody,
        }
        for role, model in custom_models.items():
            self._verify_custom_signature(
                role,
                requests[role].payload,
                keyrings[role],
            )

        self._verify_generation_join(
            custom_models=custom_models,
            custody=custody,
            requests=requests,
            observed_at=observed_at,
        )
        generation_valid_until = min(
            model.valid_until_utc for model in custom_models.values()
        )
        audit_snapshot_id, audit_exact_contracts = self._verify_p0(p0)
        if (
            audit_snapshot_id != custody.snapshot_id
            or audit_exact_contracts != custody.exact_contracts
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_AUDIT_RUNTIME_SCOPE_MISMATCH"
            )

        policy_v1_payload, policy_v1_raw = _read_exact_private_canonical_json(
            Path(
                self.settings.commodity_c_fast_execution_quality_policy_v1_path
            ).expanduser(),
            label="EXECUTION_QUALITY_POLICY_V1",
            expected_owner_uid=(
                self.settings.commodity_c_fast_execution_quality_artifact_expected_owner_uid
            ),
        )
        if not hmac.compare_digest(
            sha256_bytes(policy_v1_raw),
            self.settings.commodity_c_fast_execution_quality_policy_v1_expected_raw_sha256,
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "EXECUTION_POLICY_V1_RAW_PIN_MISMATCH"
            )
        policy_keys = self._keyring_mapping(keyrings["execution_policy"])
        policy_pin = sha256_bytes(canonical_json(policy_keys))
        policy_receipt = verify_execution_policy_freeze_v2_raw_chain(
            requests["execution_policy"].raw,
            superseded_freeze_raw=policy_v1_raw,
            trusted_public_keys=policy_keys,
            expected_trusted_public_keys_sha256=policy_pin,
        )
        policy_v2 = parse_execution_policy_freeze_v2_json(
            requests["execution_policy"].raw
        )
        policy_v1 = parse_execution_policy_freeze_json(policy_v1_raw)
        if policy_receipt.freeze_raw_sha256 != requests["execution_policy"].raw_sha256:
            raise CFastExecutionQualityProductionVerifierError(
                "EXECUTION_POLICY_EXACT_RAW_MISMATCH"
            )

        all_specs = {spec.exact_contract: spec for spec in signed_specs.specs}
        if (
            len(all_specs) != len(signed_specs.specs)
            or tuple(spec.exact_contract for spec in signed_specs.specs)
            != signed_specs.exact_contracts
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "CONTRACT_SPEC_EXACT_GENERATION_SET_INVALID"
            )
        snapshot_payload = requests["signed_snapshot"].payload
        try:
            snapshot = CommodityCFastShadowDTO.model_validate(snapshot_payload)
        except ValidationError as exc:
            raise CFastExecutionQualityProductionVerifierError(
                "SIGNED_SNAPSHOT_SCHEMA_INVALID"
            ) from exc
        snapshot_keys = self._keyring_mapping(keyrings["signed_snapshot"])

        def contract_loader(exacts: set[str]) -> dict[str, dict[str, object]]:
            if not exacts <= set(all_specs):
                raise CFastExecutionQualityProductionVerifierError(
                    "SIGNED_SNAPSHOT_CONTRACT_SPEC_COVERAGE_INCOMPLETE"
                )
            return {
                exact: {
                    "multiplier": all_specs[exact].multiplier,
                    "price_tick": all_specs[exact].price_tick,
                }
                for exact in exacts
            }

        shadow = CommodityCFastShadowService(
            settings=Settings(
                commodity_c_fast_shadow_trusted_public_keys_json=json.dumps(
                    snapshot_keys,
                    allow_nan=False,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            ),
            contract_loader=contract_loader,
            clock=lambda: observed_at,
        )
        snapshot_receipt = shadow._verify_snapshot(snapshot)
        if requests["signed_snapshot"].raw != canonical_json(snapshot_payload) + b"\n":
            raise CFastExecutionQualityProductionVerifierError(
                "SIGNED_SNAPSHOT_EXACT_RAW_MISMATCH"
            )

        plan = reload_and_verify_virtual_intent_plan(
            signed_plan.plan.model_dump(mode="json"),
            accepted_snapshot=snapshot,
            snapshot_receipt=snapshot_receipt,
            frozen_policy=policy_v1.policy,
        )
        runtime_specs = tuple(all_specs[exact] for exact in custody.exact_contracts)
        if (
            tuple(sorted({item.exact_contract for item in plan.intents}))
            != custody.exact_contracts
            or tuple(spec.exact_contract for spec in runtime_specs)
            != custody.exact_contracts
            or p0.snapshot_id != snapshot.snapshot_id
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_TYPED_INPUT_SCOPE_MISMATCH"
            )

        return {
            role: SignedArtifactVerification(
                verification=self._verification(
                    role=role,
                    request=requests[role],
                    exact_contracts=(
                        () if role == "execution_policy" else custody.exact_contracts
                    ),
                    valid_until=(
                        p0.valid_until_utc
                        if role == "signed_p0_acceptance"
                        else (
                            admission.valid_until_utc
                            if role == "collection_admission"
                            else (
                                None
                                if role
                                in {
                                    "execution_policy",
                                    "virtual_intent_plan",
                                    "contract_spec_set",
                                }
                                else generation_valid_until
                            )
                        )
                    ),
                    domains=domains[role],
                    raw_bindings=custody.artifact_raw_sha256.model_dump(mode="python"),
                ),
                preverified_plan=plan if role == "virtual_intent_plan" else None,
                source_snapshot_receipt_sha256=(
                    snapshot_receipt if role == "signed_snapshot" else None
                ),
                score_policy=policy_v2.policy if role == "execution_policy" else None,
                contract_specs=runtime_specs if role == "contract_spec_set" else None,
            )
            for role in ARTIFACT_ROLES
        }

    def _load_keyrings(self):
        paths = self._role_json_setting(
            self.settings.commodity_c_fast_execution_quality_role_keyring_paths_json,
            "ROLE_KEYRING_PATHS",
        )
        pins = self._role_json_setting(
            self.settings.commodity_c_fast_execution_quality_role_keyring_raw_sha256_json,
            "ROLE_KEYRING_RAW_SHA256",
        )
        resolved_paths = [Path(paths[role]).expanduser() for role in ARTIFACT_ROLES]
        if len(set(resolved_paths)) != len(ARTIFACT_ROLES) or Path(
            self.settings.commodity_c_fast_execution_quality_policy_v1_path
        ).expanduser() in set(resolved_paths):
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_ARTIFACT_KEYRING_PATH_COLLISION"
            )
        loaded = {}
        domains = {}
        owner = (
            self.settings.commodity_c_fast_execution_quality_artifact_expected_owner_uid
        )
        for role in ARTIFACT_ROLES:
            payload, raw = _read_exact_private_canonical_json(
                Path(paths[role]).expanduser(),
                label=f"{role.upper()}_KEYRING",
                expected_owner_uid=owner,
            )
            if not hmac.compare_digest(sha256_bytes(raw), pins[role]):
                raise CFastExecutionQualityProductionVerifierError(
                    f"{role.upper()}_KEYRING_RAW_PIN_MISMATCH"
                )
            try:
                keyring = CFastExecutionQualityRoleTrustedKeysDTO.model_validate(
                    payload
                )
            except ValidationError as exc:
                raise CFastExecutionQualityProductionVerifierError(
                    f"{role.upper()}_KEYRING_SCHEMA_INVALID"
                ) from exc
            if keyring.artifact_role != role or any(
                key.purpose != ROLE_SIGNER_PURPOSES[role]
                for key in keyring.trusted_keys
            ):
                raise CFastExecutionQualityProductionVerifierError(
                    f"{role.upper()}_KEYRING_ROLE_OR_PURPOSE_MISMATCH"
                )
            materials = []
            for key in keyring.trusted_keys:
                try:
                    material = base64.b64decode(key.public_key_base64, validate=True)
                    if len(material) != 32:
                        raise ValueError
                    Ed25519PublicKey.from_public_bytes(material)
                except (ValueError, binascii.Error) as exc:
                    raise CFastExecutionQualityProductionVerifierError(
                        f"{role.upper()}_KEYRING_MATERIAL_INVALID"
                    ) from exc
                materials.append(material)
            loaded[role] = keyring
            domains[role] = tuple(sorted(sha256_bytes(item) for item in materials))
        return loaded, domains

    @staticmethod
    def _role_json_setting(raw: str, label: str) -> dict[ArtifactRole, str]:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CFastExecutionQualityProductionVerifierError(
                f"{label}_JSON_INVALID"
            ) from exc
        if (
            not isinstance(value, dict)
            or set(value) != set(ARTIFACT_ROLES)
            or any(not isinstance(item, str) or not item for item in value.values())
        ):
            raise CFastExecutionQualityProductionVerifierError(
                f"{label}_SET_INCOMPLETE"
            )
        return value

    @staticmethod
    def _require_disjoint_domains(domains) -> None:
        seen: set[str] = set()
        for role in ARTIFACT_ROLES:
            current = set(domains[role])
            if seen & current:
                raise CFastExecutionQualityProductionVerifierError(
                    "PRODUCTION_ARTIFACT_KEY_DOMAIN_OVERLAP"
                )
            seen.update(current)

    @staticmethod
    def _keyring_mapping(keyring) -> dict[str, dict[str, str]]:
        return {
            item.key_id: {
                "public_key_base64": item.public_key_base64,
                "purpose": item.purpose,
            }
            for item in keyring.trusted_keys
        }

    @staticmethod
    def _verify_custom_signature(role, payload, keyring) -> None:
        selected = next(
            (
                item
                for item in keyring.trusted_keys
                if item.key_id == payload["signer_key_id"]
            ),
            None,
        )
        if selected is None:
            raise CFastExecutionQualityProductionVerifierError(
                f"{role.upper()}_SIGNER_NOT_TRUSTED"
            )
        unsigned = {key: value for key, value in payload.items() if key != "signature"}
        try:
            signature = base64.b64decode(payload["signature"], validate=True)
            material = base64.b64decode(selected.public_key_base64, validate=True)
            if len(signature) != 64:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(material).verify(
                signature,
                runtime_artifact_signature_message(role, unsigned),
            )
        except (ValueError, binascii.Error, InvalidSignature) as exc:
            raise CFastExecutionQualityProductionVerifierError(
                f"{role.upper()}_SIGNATURE_INVALID"
            ) from exc

    @staticmethod
    def _custom_signature_message(role: ArtifactRole, unsigned: object) -> bytes:
        return runtime_artifact_signature_message(role, unsigned)

    def _verify_generation_join(
        self,
        *,
        custom_models,
        custody,
        requests,
        observed_at,
    ) -> None:
        if any(
            model.generation_id != custody.generation_id
            or model.snapshot_id != custody.snapshot_id
            or model.exact_contracts != custody.exact_contracts
            or not model.issued_at_utc <= observed_at < model.valid_until_utc
            or model.valid_until_utc - model.issued_at_utc > timedelta(minutes=10)
            for model in custom_models.values()
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_ARTIFACT_GENERATION_OR_EXPIRY_MISMATCH"
            )
        actual = {role: requests[role].raw_sha256 for role in ARTIFACT_ROLES[:-1]}
        if custody.artifact_raw_sha256.model_dump(mode="python") != actual:
            raise CFastExecutionQualityProductionVerifierError(
                "CUSTODY_ARTIFACT_RAW_BINDING_MISMATCH"
            )
        root_path_hash = sha256_bytes(
            str(
                Path(
                    self.settings.commodity_c_fast_execution_quality_artifact_custody_root
                ).expanduser()
            ).encode("utf-8")
        )
        if (
            custody.custody_root_path_sha256
            != self.settings.commodity_c_fast_execution_quality_artifact_expected_root_path_sha256
            or custody.custody_root_path_sha256 != root_path_hash
            or custody.custody_identity_sha256
            != self.settings.commodity_c_fast_execution_quality_artifact_expected_identity_sha256
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "CUSTODY_ROOT_PIN_BINDING_MISMATCH"
            )
        if (
            custom_models["collection_admission"].signed_p0_acceptance_raw_sha256
            != actual["signed_p0_acceptance"]
            or custom_models["collection_admission"].execution_policy_raw_sha256
            != actual["execution_policy"]
            or custom_models["virtual_intent_plan"].execution_policy_raw_sha256
            != actual["execution_policy"]
            or custom_models["virtual_intent_plan"].signed_snapshot_raw_sha256
            != actual["signed_snapshot"]
            or custom_models["virtual_intent_plan"].contract_spec_set_raw_sha256
            != actual["contract_spec_set"]
            or custom_models["collection_admission"].issued_at_utc
            < custom_models["signed_p0_acceptance"].issued_at_utc
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "PRODUCTION_ARTIFACT_CROSS_ROLE_BINDING_MISMATCH"
            )

    @staticmethod
    def _decode_exact_json(value: str, label: str):
        def reject_duplicate_keys(pairs):
            payload = {}
            for key, item in pairs:
                if key in payload:
                    raise ValueError("duplicate JSON object key")
                payload[key] = item
            return payload

        def reject_constant(value):
            raise ValueError(f"non-finite JSON constant: {value}")

        try:
            raw = base64.b64decode(value, validate=True)
            payload = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_constant,
            )
        except (
            ValueError,
            binascii.Error,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise CFastExecutionQualityProductionVerifierError(
                f"{label}_EXACT_JSON_INVALID"
            ) from exc
        if (
            not isinstance(payload, dict)
            or not raw.endswith(b"\n")
            or raw.endswith(b"\n\n")
        ):
            raise CFastExecutionQualityProductionVerifierError(
                f"{label}_EXACT_JSON_LINE_ENDING_INVALID"
            )
        return payload, raw

    def _verify_p0(self, p0) -> tuple[str, tuple[str, ...]]:
        terminal, terminal_raw = self._decode_exact_json(
            p0.terminal_exact_json_base64,
            "QUERY_V6_TERMINAL",
        )
        proof, proof_raw = self._decode_exact_json(
            p0.readonly_proof_exact_json_base64,
            "QUERY_V6_READONLY_PROOF",
        )
        audit, audit_raw = self._decode_exact_json(
            p0.audit_exact_json_base64,
            "QUERY_V6_AUDIT",
        )
        try:
            terminal_schema = json.loads(_TERMINAL_SCHEMA.read_text(encoding="utf-8"))
            proof_schema = json.loads(
                _READONLY_PROOF_SCHEMA.read_text(encoding="utf-8")
            )
            audit_schema = json.loads(_AUDIT_SCHEMA.read_text(encoding="utf-8"))
            audit_v1_schema = json.loads(_AUDIT_V1_SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator(
                terminal_schema,
                format_checker=FormatChecker(),
            ).validate(terminal)
            Draft202012Validator(
                proof_schema,
                format_checker=FormatChecker(),
            ).validate(proof)
            audit_registry = Registry().with_resource(
                _AUDIT_V1_RESOURCE_URI,
                Resource.from_contents(audit_v1_schema),
            )
            Draft202012Validator(
                audit_schema,
                format_checker=FormatChecker(),
                registry=audit_registry,
            ).validate(audit)
        except Exception as exc:
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_EVIDENCE_SCHEMA_INVALID"
            ) from exc
        if (
            sha256_bytes(terminal_raw) != p0.terminal_raw_sha256
            or sha256_bytes(canonical_json(terminal)) != p0.terminal_canonical_sha256
            or sha256_bytes(proof_raw) != p0.readonly_proof_raw_sha256
            or sha256_bytes(canonical_json(proof)) != p0.readonly_proof_canonical_sha256
            or sha256_bytes(audit_raw) != p0.audit_raw_sha256
            or sha256_bytes(canonical_json(audit)) != p0.audit_canonical_sha256
            or terminal["terminal_state"] != "COMPLETED_PASS"
            or terminal["p0_pass"] is not True
            or terminal["executable_release_raw_sha256"]
            != p0.executable_release_raw_sha256
            or terminal["executable_release_canonical_sha256"]
            != p0.executable_release_canonical_sha256
            or terminal["foundation_raw_sha256"] != p0.foundation_raw_sha256
            or terminal["foundation_canonical_sha256"] != p0.foundation_canonical_sha256
            or terminal["execution_adapter_sha256"] != p0.execution_adapter_sha256
            or terminal["artifact_sha256"]["readonly_proof"]
            != p0.readonly_proof_raw_sha256
            or terminal["artifact_sha256"]["audit_json"] != p0.audit_raw_sha256
            or proof["snapshot_id"] != p0.snapshot_id
            or proof["audit_evidence_sha256"] != p0.audit_raw_sha256
            or audit["snapshot_id"] != p0.snapshot_id
            or audit["manifest_sha256"] != proof["manifest_sha256"]
            or audit["summary"]["p0_pass"] is not True
            or audit["summary"]["overall_conclusion"] != "L5_USABLE"
            or audit["summary"]["expected_products"] != len(PRODUCTS)
            or audit["summary"]["observed_products"] != len(PRODUCTS)
            or audit["blockers"] != []
            or audit["read_only"] is not True
            or audit["database_mutations"] != 0
            or proof.get("endpoint_binding_verified") is not True
            or proof["database_mutations"] != 0
            or proof["write_probe_attempted"] is not False
            or terminal["write_probe_attempted"] is not False
            or terminal["database_mutations_observed"] != 0
            or terminal["web_bridge_rpc_calls"] != 0
            or terminal["orders_sent"] != 0
            or terminal["positions_modified"] != 0
            or terminal["dispatch_changed"] is not False
            or self._utc_datetime(terminal["ended_at"], "QUERY_V6_TERMINAL_END")
            > p0.issued_at_utc
            or self._utc_datetime(proof["generated_at"], "READONLY_PROOF_GENERATED")
            > p0.issued_at_utc
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_EVIDENCE_BINDING_INVALID"
            )
        for field, expected in (
            (
                "readonly_preflight_canonical_sha256",
                sha256_bytes(canonical_json(proof["preflight"])),
            ),
            (
                "readonly_postflight_canonical_sha256",
                sha256_bytes(canonical_json(proof["postflight"])),
            ),
        ):
            if terminal[field] != expected:
                raise CFastExecutionQualityProductionVerifierError(
                    "QUERY_V6_P0_READONLY_PROOF_BINDING_INVALID"
                )
        if proof["preflight"] != proof["postflight"]:
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_READONLY_PROOF_STABILITY_INVALID"
            )

        audit_generated = self._utc_datetime(
            audit["generated_at"],
            "QUERY_V6_AUDIT_GENERATED",
        )
        if (
            not p0.issued_at_utc - timedelta(minutes=10)
            <= audit_generated
            <= p0.issued_at_utc
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_AUDIT_STALE_OR_POSTDATED"
            )
        proof_generated = self._utc_datetime(
            proof["generated_at"],
            "READONLY_PROOF_GENERATED",
        )
        terminal_ended = self._utc_datetime(
            terminal["ended_at"],
            "QUERY_V6_TERMINAL_END",
        )
        if not audit_generated <= proof_generated <= terminal_ended:
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_EVIDENCE_TIME_ORDER_INVALID"
            )

        current_contracts = [
            item for item in audit["contracts"] if item["role"] == "current"
        ]
        by_product = {item["product"]: item for item in current_contracts}
        product_results = {item["product"]: item for item in audit["products"]}
        if (
            len(current_contracts) != len(PRODUCTS)
            or len(by_product) != len(PRODUCTS)
            or set(by_product) != set(PRODUCTS)
            or len(product_results) != len(PRODUCTS)
            or set(product_results) != set(PRODUCTS)
            or any(
                item["classification"] != "L5_USABLE"
                for item in product_results.values()
            )
            or any(
                item["classification"] != "L5_USABLE"
                or re.fullmatch(
                    rf"{re.escape(C_FAST_PRODUCT_SPECS_V1[product]['exchange'])}\."
                    rf"{re.escape(product)}[0-9]{{4}}",
                    item["exact_contract"],
                )
                is None
                for product, item in by_product.items()
            )
        ):
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_AUDIT_EXACT_CONTRACT_SET_INVALID"
            )
        derived_contracts = tuple(
            sorted(item["exact_contract"] for item in current_contracts)
        )
        if derived_contracts != p0.exact_contracts:
            raise CFastExecutionQualityProductionVerifierError(
                "QUERY_V6_P0_AUDIT_SIGNED_SCOPE_MISMATCH"
            )
        return audit["snapshot_id"], derived_contracts

    @staticmethod
    def _utc_datetime(value: object, label: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError
            return parsed.astimezone(timezone.utc)
        except ValueError as exc:
            raise CFastExecutionQualityProductionVerifierError(
                f"{label}_INVALID"
            ) from exc

    @staticmethod
    def _verification(
        *,
        role,
        request,
        exact_contracts,
        valid_until,
        domains,
        raw_bindings,
    ):
        return CFastExecutionQualityArtifactVerificationDTO.model_validate(
            {
                "schema_version": "commodity_c_fast_execution_quality_artifact_verification_v1",
                "artifact_role": role,
                "candidate_id": "C_FAST_CROSS_SECTION_NEUTRAL",
                "raw_sha256": request.raw_sha256,
                "canonical_sha256": request.canonical_sha256,
                "valid_until_utc": valid_until,
                "exact_contracts": exact_contracts,
                "bound_artifact_raw_sha256": {
                    bound: raw_bindings[bound] for bound in _BINDINGS[role]
                },
                "verified_signer_domain_public_key_sha256": domains,
                "signature_verified": True,
                "semantic_contract_verified": True,
                **_FALSE_AUTHORITY,
            }
        )


__all__ = [
    "CUSTOM_SIGNATURE_DOMAIN",
    "CFastExecutionQualityProductionVerifierError",
    "CommodityCFastExecutionQualityProductionArtifactVerifier",
    "ROLE_SIGNER_PURPOSES",
    "runtime_artifact_signature_message",
]
