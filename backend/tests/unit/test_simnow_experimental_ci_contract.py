"""Permanent CI contract coverage for the isolated experimental lane."""

from scripts.ci.classify_changes import classify


def test_registered_experimental_glue_isolated_from_heavy_ci() -> None:
    for path in (
        "scripts/simnow_experimental_materialize_target.py",
        "scripts/simnow_experimental_run_once.py",
        "backend/tests/unit/test_simnow_experimental_ci_contract.py",
    ):
        result = classify([path])
        assert result["simnow_experimental_changed"] is True, path
        assert not any(
            value
            for key, value in result.items()
            if key != "simnow_experimental_changed"
        ), path


def test_unregistered_experimental_script_uses_normal_ci() -> None:
    result = classify(["scripts/simnow_experimental_future_helper.py"])
    assert result["backend_changed"] is True
    assert result["image_changed"] is True
    assert result["simnow_experimental_changed"] is False
