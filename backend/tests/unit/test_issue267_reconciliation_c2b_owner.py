from pathlib import Path

import pytest
from app.services.deployment_drain import (
    DeploymentDrainError,
    DeploymentDrainService,
)


class Owner:
    def reconcile(self) -> None:
        return None

    def snapshot(self) -> None:
        return None

    def recheck(self) -> None:
        return None


def test_reconciliation_owner_binding_is_exact_and_idempotent(
    tmp_path: Path,
) -> None:
    service = DeploymentDrainService(tmp_path)
    owner = Owner()

    service.bind_reconciliation_provider(owner, owner.reconcile)
    service.bind_reconciliation_provider(owner, owner.reconcile)
    service.assert_reconciliation_provider(owner, owner.reconcile)

    with pytest.raises(TypeError):
        service.bind_reconciliation_provider(owner, Owner().reconcile)


def test_reconciliation_owner_cannot_conflict_with_online_owner(
    tmp_path: Path,
) -> None:
    service = DeploymentDrainService(tmp_path)
    online = Owner()
    attacker = Owner()
    service.bind_online_snapshot_provider(online, online.snapshot)
    service.bind_online_recheck_provider(online, online.recheck)

    with pytest.raises(DeploymentDrainError) as caught:
        service.bind_reconciliation_provider(attacker, attacker.reconcile)
    assert caught.value.code == "DEPLOYMENT_RECONCILIATION_OWNER_CONFLICT"

    service.bind_reconciliation_provider(online, online.reconcile)
    service.assert_reconciliation_provider(online, online.reconcile)

    with pytest.raises(DeploymentDrainError) as caught:
        service.assert_reconciliation_provider(attacker, attacker.reconcile)
    assert caught.value.code == "DEPLOYMENT_RECONCILIATION_OWNER_INVALID"


def test_reconciliation_binding_rejects_provider_replacement(
    tmp_path: Path,
) -> None:
    service = DeploymentDrainService(tmp_path)
    owner = Owner()
    service.bind_reconciliation_provider(owner, owner.reconcile)

    with pytest.raises(DeploymentDrainError) as caught:
        service.bind_reconciliation_provider(owner, owner.snapshot)
    assert caught.value.code == "DEPLOYMENT_RECONCILIATION_OWNER_CONFLICT"
