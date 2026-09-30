"""Verify the existing isolated R1 scientific chain before Memory feedback."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from research_lab.agent_control.contracts import _clean_for_canonical
from research_lab.alpha_discovery.hypothesis import compute_scientific_identity_hash, compute_semantic_hash

REF_KINDS = ("task", "spec", "run", "manifest", "evidence")


def _refs(refs: Any, kind: str) -> dict[str, dict]:
    if not isinstance(refs, (list, tuple)) or not refs:
        raise ValueError(f"R1 lineage missing {kind} refs")
    result = {}
    for ref in refs:
        if (not isinstance(ref, dict) or not ref.get(f"{kind}_id")
                or not ref.get("content_hash") or ref[f"{kind}_id"] in result):
            raise ValueError(f"R1 lineage invalid/duplicate {kind} ref")
        result[ref[f"{kind}_id"]] = ref
    return result


def verify_r1_scientific_lineage(evidence: dict, memory_reader: Any, store: Any) -> None:
    """Check all R1 Memory records, including ones outside the bounded view.

    ResultStore remains the cryptographic receipt verifier; local summary fields
    must agree with its receipts and the existing domain Memory records.
    """
    records = memory_reader.get_all_records()
    if not records:
        raise ValueError("R1 lineage missing scientific Memory records")
    by_id = {r.record_id: r for r in records}
    if len(by_id) != len(records):
        raise ValueError("R1 lineage duplicate Memory record")
    covered_records: set[str] = set()
    covered_runs: set[str] = set()
    for integration in evidence["integrations"]:
        if not isinstance(integration, dict) or integration.get("engineering_status") != "COMPLETED":
            raise ValueError("R1 scientific integration incomplete")
        payloads = integration.get("memory_records")
        if not isinstance(payloads, list) or not payloads:
            raise ValueError("R1 lineage missing integration Memory records")
        owned = []
        for payload in payloads:
            rid = payload.get("record_id") if isinstance(payload, dict) else None
            record = by_id.get(rid)
            if record is None or rid in covered_records:
                raise ValueError("R1 lineage missing/duplicate integration Memory record")
            if _clean_for_canonical(payload) != _clean_for_canonical(asdict(record)):
                raise ValueError("R1 lineage integration Memory payload mismatch")
            if record.record_type != "evaluation":
                raise ValueError("R1 lineage requires scientific evaluation Memory")
            if (record.scientific_identity_hash != compute_scientific_identity_hash(record.hypothesis_payload)
                    or record.semantic_hash != compute_semantic_hash(record.hypothesis_payload)
                    or record.hypothesis_ref.get("hypothesis_id") != record.hypothesis_id
                    or record.hypothesis_ref.get("content_hash") != record.content_hash
                    or record.hypothesis_payload.get("hypothesis_content_hash") != record.content_hash
                    or not record.plan_ref or not record.plan_payload
                    or record.plan_ref.get("plan_id") != record.plan_payload.get("plan_id")
                    or record.plan_ref.get("content_hash") != record.plan_payload.get("plan_content_hash")
                    or record.plan_payload.get("hypothesis_ref") != record.hypothesis_ref
                    or record.plan_payload.get("scientific_identity_hash") != record.scientific_identity_hash
                    or not record.critic_decision_payload
                    or record.critic_decision_payload.get("hypothesis_ref") != record.hypothesis_ref
                    or record.critic_decision_payload.get("decision") != record.decision):
                raise ValueError("R1 lineage inconsistent Memory identity")
            for name, value in (("hypothesis_id", record.hypothesis_id),
                                ("hypothesis_content_hash", record.content_hash),
                                ("scientific_identity_hash", record.scientific_identity_hash)):
                if integration.get(name) != value:
                    raise ValueError(f"R1 lineage integration {name} mismatch")
            covered_records.add(rid)
            owned.append(record)
        final = owned[-1]
        if (integration.get("memory_record_id") != final.record_id
                or integration.get("plan_id") != final.plan_ref["plan_id"]
                or integration.get("plan_content_hash") != final.plan_ref["content_hash"]
                or integration.get("scientific_decision") != final.decision
                or _clean_for_canonical(integration.get("critic_decision"))
                != _clean_for_canonical(final.critic_decision_payload)):
            raise ValueError("R1 lineage final scientific integration mismatch")
        for kind in REF_KINDS:
            declared = _refs(integration.get(f"{kind}_refs"), kind)
            actual = _refs([ref for r in owned for ref in getattr(r, f"{kind}_refs")], kind)
            if _clean_for_canonical(declared) != _clean_for_canonical(actual):
                raise ValueError(f"R1 lineage incomplete/mismatched integration {kind} refs")
        for record in owned:
            refs = {kind: _refs(getattr(record, f"{kind}_refs"), kind) for kind in REF_KINDS}
            resolved = {kind: set() for kind in REF_KINDS}
            for run_id, run_ref in refs["run"].items():
                if run_id in covered_runs:
                    raise ValueError("R1 lineage duplicate run across Memory records")
                receipts = store.query_v2_runs(run_id=run_id, verify=True)
                if len(receipts) != 1:
                    raise ValueError("R1 lineage receipt missing or ambiguous")
                receipt = receipts[0]
                for kind in REF_KINDS:
                    observed = receipt.get(kind, {})
                    object_id = observed.get("object_id")
                    expected = refs[kind].get(object_id)
                    if (expected is None or observed.get("content_hash") != expected["content_hash"]
                            or (kind in {"task", "spec", "manifest"}
                                and observed.get("revision") != expected.get("revision"))
                            or (kind == "evidence" and expected.get("revision") != "rev.1")):
                        raise ValueError(f"R1 lineage receipt {kind} identity/hash mismatch")
                    resolved[kind].add(object_id)
                if receipt.get("run_status") != run_ref.get("run_status"):
                    raise ValueError("R1 lineage receipt run status mismatch")
                covered_runs.add(run_id)
            if any(resolved[kind] != set(refs[kind]) for kind in REF_KINDS):
                raise ValueError("R1 lineage Memory refs not fully covered by receipts")
    if covered_records != set(by_id):
        raise ValueError("R1 lineage Memory record omitted from integration summary")
