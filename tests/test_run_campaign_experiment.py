from types import SimpleNamespace

from run_campaign import annotate_experiment_telemetry


def test_annotate_experiment_telemetry_preserves_campaign_identity():
    result = SimpleNamespace(
        telemetry={
            "campaign_id": "campaign-uuid",
            "event": {"type": "adversarial_test"},
        }
    )

    annotate_experiment_telemetry([result], "exp-20260828-test")

    assert result.telemetry["campaign_id"] == "campaign-uuid"
    assert result.telemetry["experiment_id"] == "exp-20260828-test"
    assert result.telemetry["experiment"] == {
        "id": "exp-20260828-test"
    }


def test_annotate_experiment_telemetry_leaves_normal_campaign_unchanged():
    result = SimpleNamespace(telemetry={"campaign_id": "campaign-uuid"})

    annotate_experiment_telemetry([result], None)

    assert result.telemetry == {"campaign_id": "campaign-uuid"}
