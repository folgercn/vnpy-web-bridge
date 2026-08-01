#!/usr/bin/env python3
"""CI-only real-builder query-v5 composition probe; never emits authority."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from typing import Any
import urllib.parse
import urllib.request

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from c_fast_t1 import create_query_v4_source_bundle as v4_producer  # noqa: E402
from c_fast_t1 import create_query_v5_source_bundle as v5_producer  # noqa: E402
from c_fast_t1 import verify_query_v4_image_attestation as query_v4  # noqa: E402
from c_fast_t1 import verify_query_v5_image_attestation as query_v5  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _request(url: str, *, accept: str | None = None) -> tuple[bytes, str]:
    headers = {} if accept is None else {"Accept": accept}
    with urllib.request.urlopen(  # noqa: S310 - CI uses explicit local registry
        urllib.request.Request(url, headers=headers), timeout=60
    ) as response:
        raw = response.read()
        digest = response.headers.get("Docker-Content-Digest", "")
    if digest and digest != "sha256:" + _sha256(raw):
        raise RuntimeError("registry response digest does not match raw bytes")
    return raw, digest


def _registry_url(registry: str, repository: str, kind: str, value: str) -> str:
    encoded = urllib.parse.quote(value, safe=":@")
    return f"{registry.rstrip('/')}/v2/{repository}/{kind}/{encoded}"


def export_registry_oci(
    registry: str,
    repository: str,
    reference: str,
    output: Path,
) -> str:
    accept = ", ".join((OCI_INDEX, OCI_MANIFEST, DOCKER_INDEX, DOCKER_MANIFEST))
    raw, digest = _request(
        _registry_url(registry, repository, "manifests", reference),
        accept=accept,
    )
    document = json.loads(raw)
    media_type = document.get("mediaType")
    if media_type in {OCI_INDEX, DOCKER_INDEX}:
        candidates = [
            descriptor
            for descriptor in document.get("manifests", [])
            if descriptor.get("platform", {}).get("architecture") == "amd64"
            and descriptor.get("platform", {}).get("os") == "linux"
        ]
        if len(candidates) != 1:
            raise RuntimeError("registry index has no unique linux/amd64 image")
        digest = candidates[0]["digest"]
        raw, returned = _request(
            _registry_url(registry, repository, "manifests", digest),
            accept=accept,
        )
        if returned and returned != digest:
            raise RuntimeError("registry platform manifest digest drifted")
        document = json.loads(raw)
        media_type = document.get("mediaType")
    if media_type != OCI_MANIFEST:
        raise RuntimeError("real-builder probe requires OCI image media types")
    digest = "sha256:" + _sha256(raw)
    blobs: dict[str, bytes] = {"blobs/sha256/" + digest.removeprefix("sha256:"): raw}
    for descriptor in [document["config"], *document["layers"]]:
        blob_digest = descriptor["digest"]
        blob, _unused = _request(
            _registry_url(registry, repository, "blobs", blob_digest)
        )
        if len(blob) != descriptor["size"] or "sha256:" + _sha256(blob) != blob_digest:
            raise RuntimeError("registry blob descriptor drifted")
        blobs["blobs/sha256/" + blob_digest.removeprefix("sha256:")] = blob
    index = {
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": [
            {
                "mediaType": OCI_MANIFEST,
                "digest": digest,
                "size": len(raw),
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    members = {
        "oci-layout": _canonical({"imageLayoutVersion": "1.0.0"}),
        "index.json": _canonical(index),
        **blobs,
    }
    ordered_names = ["oci-layout", "index.json", *sorted(blobs)]
    stream = io.BytesIO()
    with tarfile.open(
        fileobj=stream, mode="w:", format=tarfile.USTAR_FORMAT
    ) as archive:
        for name in ordered_names:
            content = members[name]
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o644
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = 0
            archive.addfile(member, io.BytesIO(content))
    output.write_bytes(stream.getvalue())
    return digest


def _v4_evidence(
    source: dict[str, Any],
    commit: str,
    oci: dict[str, Any],
    reference: str,
) -> dict[str, Any]:
    return {
        "schema_version": query_v4.EVIDENCE_SCHEMA_VERSION,
        "capture_kind": "unsigned_external_query_v4_oci_layout_capture_v1",
        "captured_at": "2026-08-01T00:00:00Z",
        "producer": {"tool": "ci-real-build-probe", "tool_version": "1"},
        "build_provenance_verified": False,
        "registry_provenance_verified": False,
        "source_commit_sha": commit,
        "source_bundle_archive_sha256": _sha256(source["bundle_raw"]),
        "source_manifest_raw_sha256": _sha256(source["manifest_raw"]),
        "source_manifest_canonical_sha256": _sha256(
            query_v4.canonical_json(source["manifest"])
        ),
        "build": {
            "platform": "linux/amd64",
            "context_kind": "exact_query_v4_source_bundle_v1",
            "containerfile_sha256": source["containerfile_sha256"],
            "base_image_digest": query_v4._delegate.BASE_IMAGE_DIGEST,
            "direct_dependencies": query_v4._delegate.EXPECTED_DEPENDENCIES,
        },
        "image": {
            "reference": reference,
            "digest": oci["manifest_digest"],
            "id": oci["config_digest"],
            "export_sha256": _sha256(oci["archive_raw"]),
            "rootfs_layer_digests": oci["layer_digests"],
            "config": oci["config"],
            "bundle_files": oci["runtime_bundle"],
            "forbidden_path_matches": [],
            "unexpected_bundle_paths": [],
            "signer_or_private_key_paths": [],
        },
        "sensitive_material_present": False,
        "authority_granted": False,
    }


def _ci_runtime_identity() -> query_v5.QueryV5AttestationRuntimeIdentity:
    values = {
        field: _sha256(("ci-real-build-probe:" + field).encode())
        for field in query_v5.QueryV5AttestationRuntimeIdentity.__dataclass_fields__
        if field.endswith("_sha256")
    }
    return query_v5.QueryV5AttestationRuntimeIdentity(
        runtime_image_digest="sha256:" + "a" * 64,
        **values,
        isolated_flags_verified=True,
        pre_import_runtime_verified=True,
        source_closure_retained=True,
        immutable_runtime_verified=True,
    )


def attest_real_builds(
    commit: str,
    v4_archive: Path,
    v4_reference: str,
    v5_archive: Path,
    v5_reference: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="query-v5-real-oci-") as temporary:
        root = Path(temporary)
        v4_bundle_raw = v4_producer.build_source_bundle(ROOT, commit)[0]
        v4_bundle = root / "query-v4-source.tar"
        v4_bundle.write_bytes(v4_bundle_raw)
        v4_source = query_v4.derive_source_facts(v4_bundle, commit)
        v4_oci = query_v4.derive_oci_facts(
            v4_archive,
            commit,
            v4_source["runtime_bundle"],
        )
        v4_evidence = root / "query-v4-evidence.json"
        v4_evidence.write_bytes(
            _canonical(_v4_evidence(v4_source, commit, v4_oci, v4_reference))
        )
        v4_report = query_v4.verify_query_v4_image_evidence(
            v4_evidence, v4_bundle, v4_archive, commit
        )
        v4_report_raw = (
            json.dumps(v4_report, sort_keys=True, indent=2) + "\n"
        ).encode()
        v4_report_path = root / "query-v4-attestation.json"
        v4_report_path.write_bytes(v4_report_raw)

        v5_bundle_raw = v5_producer.build_source_bundle(ROOT, commit)[0]
        v5_bundle = root / "query-v5-source.tar"
        v5_bundle.write_bytes(v5_bundle_raw)
        v5_source = query_v5._source_facts(v5_bundle, commit)
        base = query_v5._load_oci_state(v4_archive, "query-v4")
        final = query_v5._load_oci_state(v5_archive, "query-v5")
        composition = query_v5._validate_final_oci(
            base, final, v4_report, v5_source, commit
        )
        image = {
            "reference": v5_reference,
            "digest": final["manifest_digest"],
            "id": final["config_digest"],
            "export_sha256": _sha256(final["archive_raw"]),
            "rootfs_layer_digests": final["layer_digests"],
            "rootfs_diff_ids": final["diff_ids"],
            "config": {
                "user": final["config"]["User"],
                "working_dir": final["config"]["WorkingDir"],
                "entrypoint": final["config"]["Entrypoint"],
                "relevant_environment": composition["environment"],
                "labels": composition["labels"],
            },
            "bundle_files": composition["runtime_bundle"],
            "overlay_touched_paths": composition["overlay_touched_paths"],
            "forbidden_path_matches": [],
            "unexpected_bundle_paths": [],
            "signer_or_private_key_paths": [],
        }
        evidence = {
            "schema_version": query_v5.EVIDENCE_SCHEMA_VERSION,
            "capture_kind": "unsigned_external_query_v5_final_oci_composition_capture_v1",
            "captured_at": "2026-08-01T00:01:00Z",
            "producer": {"tool": "ci-real-build-probe", "tool_version": "1"},
            "query_v4": {
                "content_attestation_raw_sha256": _sha256(v4_report_raw),
                "content_attestation_canonical_sha256": _sha256(
                    query_v5.canonical_json(v4_report)
                ),
                "oci_layout_archive_sha256": _sha256(base["archive_raw"]),
                "image_reference": v4_report["image_reference"],
                "image_digest": v4_report["image_digest"],
                "image_id": v4_report["image_id"],
            },
            "source_commit_sha": commit,
            "source_bundle_archive_sha256": _sha256(v5_source["bundle_raw"]),
            "source_manifest_raw_sha256": _sha256(v5_source["manifest_raw"]),
            "source_manifest_canonical_sha256": _sha256(
                query_v5.canonical_json(v5_source["manifest"])
            ),
            "build": {
                "platform": "linux/amd64",
                "context_kind": "exact_query_v5_source_bundle_v1",
                "containerfile_sha256": v5_source["containerfile_sha256"],
                "query_v4_base_image_reference": v4_report["image_reference"],
                "query_v4_base_image_digest": v4_report["image_digest"],
            },
            "image": image,
            "build_provenance_verified": False,
            "registry_provenance_verified": False,
            "image_built_here": False,
            "sensitive_material_present": False,
            "authority_granted": False,
        }
        v5_evidence = root / "query-v5-evidence.json"
        v5_evidence.write_bytes(_canonical(evidence))
        query_v5.install_verified_runtime_identity(_ci_runtime_identity(), lambda: None)
        return query_v5.verify_query_v5_image_evidence(
            v4_evidence,
            v4_bundle,
            v4_archive,
            v4_report_path,
            commit,
            v5_evidence,
            v5_bundle,
            v5_archive,
            commit,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export-registry-oci")
    export.add_argument("--registry", required=True)
    export.add_argument("--repository", required=True)
    export.add_argument("--reference", required=True)
    export.add_argument("--output", type=Path, required=True)
    attest = subparsers.add_parser("attest")
    attest.add_argument("--source-commit-sha", required=True)
    attest.add_argument("--query-v4-oci", type=Path, required=True)
    attest.add_argument("--query-v4-image-reference", required=True)
    attest.add_argument("--query-v5-oci", type=Path, required=True)
    attest.add_argument("--query-v5-image-reference", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "export-registry-oci":
        digest = export_registry_oci(
            args.registry, args.repository, args.reference, args.output
        )
        print(f"image_digest={digest}")
        return 0
    report = attest_real_builds(
        args.source_commit_sha,
        args.query_v4_oci,
        args.query_v4_image_reference,
        args.query_v5_oci,
        args.query_v5_image_reference,
    )
    print(f"status={report['status']}")
    print("real_containerfile_build_verified=true")
    print("authority_granted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
