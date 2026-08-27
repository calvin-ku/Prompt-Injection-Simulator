import pytest

from attack_engine.orchestrator import (
    CampaignOrchestrator,
)


def test_campaign_rejects_zero_variants():
    orchestrator = CampaignOrchestrator(
        engine=None
    )

    with pytest.raises(
        ValueError,
        match="variants_per_attack",
    ):
        orchestrator.run_campaign(
            attacks={},
            owasp_mapping={},
            atlas_mapping={},
            seed=12345,
            variants_per_attack=0,
        )