import json
from argparse import Namespace

import pytest

from run_experiment import (
    build_campaign_command,
    summarize_events,
    validate_paired_campaigns,
    write_experiment_summary,
)


def attack_event(
    *,
    attack_id="ATTACK-INJ-DIR-01",
    variant_index=1,
    payload="ignore prior instructions",
    variant_seed=12346,
    experiment_id="exp-test",
):
    return {
        "experiment_id": experiment_id,
        "event": {"type": "adversarial_test"},
        "attack": {"id": attack_id, "variant_index": variant_index},
        "mutation": {"mutated_payload": payload},
        "reproducibility": {
            "variant_seed": variant_seed,
            "generation_attempt": 1,
        },
    }


def write_jsonl(path, events):
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )


def experiment_args():
    return Namespace(
        attack_catalog="custom/attacks.json",
        owasp_mapping="custom/owasp.json",
        atlas_mapping="custom/atlas.json",
        benign_catalog="custom/benign.json",
        attack="ATTACK-INJ-DIR-01",
        mutations="base64,homoglyph",
        seed=444,
        random_depth=4,
        variants_per_attack=25,
        target="local",
        target_mode="vulnerable",
        environment="test",
        include_benign=True,
        benign_only=False,
    )


def test_build_campaign_command_forwards_all_output_affecting_options(tmp_path):
    command = build_campaign_command(
        experiment_args(),
        "monitor",
        tmp_path / "monitor.jsonl",
        "exp-test",
    )

    assert "--mutations" in command
    assert command[command.index("--mutations") + 1] == "base64,homoglyph"
    assert command[command.index("--seed") + 1] == "444"
    assert command[command.index("--random-depth") + 1] == "4"
    assert command[command.index("--firewall-mode") + 1] == "monitor"
    assert command[command.index("--experiment-id") + 1] == "exp-test"
    assert "--include-benign" in command


def test_validate_paired_campaigns_accepts_identical_variants(tmp_path):
    monitor_path = tmp_path / "monitor.jsonl"
    block_path = tmp_path / "block.jsonl"
    events = [
        attack_event(variant_index=1, variant_seed=11),
        attack_event(variant_index=2, variant_seed=12),
        {
            "experiment_id": "exp-test",
            "event": {"type": "benign_test"},
        },
    ]
    write_jsonl(monitor_path, events)
    write_jsonl(block_path, events)

    assert validate_paired_campaigns(
        monitor_path,
        block_path,
        "exp-test",
    ) == 2


def test_validate_paired_campaigns_rejects_payload_mismatch(tmp_path):
    monitor_path = tmp_path / "monitor.jsonl"
    block_path = tmp_path / "block.jsonl"
    write_jsonl(monitor_path, [attack_event(payload="monitor")])
    write_jsonl(block_path, [attack_event(payload="block")])

    with pytest.raises(ValueError, match="mismatch"):
        validate_paired_campaigns(
            monitor_path,
            block_path,
            "exp-test",
        )


def test_summary_is_last_completion_marker_and_counts_events(tmp_path):
    events_path = tmp_path / "events.jsonl"
    write_jsonl(
        events_path,
        [attack_event(), {"event": {"type": "benign_test"}}],
    )
    counts = summarize_events(events_path)
    summary_path = tmp_path / "experiment_summary.jsonl"
    args = experiment_args()

    write_experiment_summary(
        summary_path,
        args,
        "exp-test",
        counts,
        counts,
        paired_attack_variants=1,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["experiment_id"] == "exp-test"
    assert summary["event"]["type"] == "experiment_summary"
    assert summary["experiment"]["status"] == "completed"
    assert summary["experiment"]["monitor"] == {
        "total_events": 2,
        "adversarial_events": 1,
        "benign_events": 1,
    }
