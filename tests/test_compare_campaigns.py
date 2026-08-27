from telemetry.compare_campaigns import (
    calculate_comparison,
    format_report,
)


def make_attack_event(
    attack_id: str,
    variant_index: int,
    payload: str,
    variant_seed: int,
    attack_succeeded: bool,
    defense_detected: bool,
    blocked: bool,
):
    return {
        "event": {
            "type": "adversarial_test",
        },
        "attack": {
            "id": attack_id,
            "variant_index": variant_index,
        },
        "mutation": {
            "mutated_payload": payload,
        },
        "reproducibility": {
            "variant_seed": variant_seed,
        },
        "result": {
            "attack_succeeded": attack_succeeded,
            "defense_detected": defense_detected,
            "blocked": blocked,
        },
    }


def make_benign_event(
    sample_id: str,
    defense_detected: bool,
    false_positive: bool,
    blocked: bool,
):
    return {
        "event": {
            "type": "benign_test",
        },
        "sample": {
            "id": sample_id,
            "expected_result": "allowed",
        },
        "result": {
            "defense_detected": defense_detected,
            "false_positive": false_positive,
            "blocked": blocked,
        },
    }


def test_identical_campaign_variants_pair_correctly():
    monitor_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="same-payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=False,
        )
    ]

    block_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="same-payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=True,
        )
    ]

    comparison = calculate_comparison(
        monitor_events=monitor_events,
        block_events=block_events,
    )

    pairing = comparison["pairing"]

    assert pairing["paired_variants"] == 1
    assert pairing["monitor_only_variants"] == 0
    assert pairing["block_only_variants"] == 0
    assert pairing["payload_mismatches"] == 0
    assert pairing["seed_mismatches"] == 0


def test_payload_mismatch_is_detected():
    monitor_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="monitor-payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=False,
        )
    ]

    block_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="different-block-payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=True,
        )
    ]

    comparison = calculate_comparison(
        monitor_events=monitor_events,
        block_events=block_events,
    )

    assert (
        comparison["pairing"]["payload_mismatches"]
        == 1
    )


def test_seed_mismatch_is_detected():
    monitor_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="same-payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=False,
        )
    ]

    block_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="same-payload",
            variant_seed=999,
            attack_succeeded=False,
            defense_detected=True,
            blocked=True,
        )
    ]

    comparison = calculate_comparison(
        monitor_events=monitor_events,
        block_events=block_events,
    )

    assert (
        comparison["pairing"]["seed_mismatches"]
        == 1
    )


def test_monitor_success_blocked_in_enforcement_counts_as_prevented():
    monitor_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="payload",
            variant_seed=123,
            attack_succeeded=True,
            defense_detected=True,
            blocked=False,
        )
    ]

    block_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=True,
        )
    ]

    comparison = calculate_comparison(
        monitor_events=monitor_events,
        block_events=block_events,
    )

    prevention = comparison["prevention"]

    assert prevention["monitor_successes"] == 1
    assert prevention["prevented_successes"] == 1
    assert prevention["unprevented_successes"] == 0
    assert prevention["prevention_rate"] == 100.0

    attack_stats = (
        comparison["per_attack"]["ATTACK-1"]
    )

    assert attack_stats["monitor_successes"] == 1
    assert attack_stats["prevented_successes"] == 1
    assert attack_stats["prevention_rate"] == 100.0


def test_no_monitor_successes_produces_na_prevention_rate():
    monitor_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=False,
        )
    ]

    block_events = [
        make_attack_event(
            attack_id="ATTACK-1",
            variant_index=1,
            payload="payload",
            variant_seed=123,
            attack_succeeded=False,
            defense_detected=True,
            blocked=True,
        )
    ]

    comparison = calculate_comparison(
        monitor_events=monitor_events,
        block_events=block_events,
    )

    assert (
        comparison["prevention"]["prevention_rate"]
        is None
    )

    assert (
        comparison[
            "per_attack"
        ]["ATTACK-1"]["prevention_rate"]
        is None
    )

    report = format_report(
        comparison
    )

    assert "Prevention rate: N/A" in report


def test_benign_impact_is_compared_between_campaigns():
    monitor_events = [
        make_benign_event(
            sample_id="BENIGN-1",
            defense_detected=True,
            false_positive=True,
            blocked=False,
        ),
        make_benign_event(
            sample_id="BENIGN-2",
            defense_detected=False,
            false_positive=False,
            blocked=False,
        ),
    ]

    block_events = [
        make_benign_event(
            sample_id="BENIGN-1",
            defense_detected=True,
            false_positive=True,
            blocked=False,
        ),
        make_benign_event(
            sample_id="BENIGN-2",
            defense_detected=False,
            false_positive=False,
            blocked=False,
        ),
    ]

    comparison = calculate_comparison(
        monitor_events=monitor_events,
        block_events=block_events,
    )

    benign = comparison["benign"]

    assert benign["monitor_samples"] == 2
    assert benign["block_samples"] == 2

    assert (
        benign["monitor_false_positives"]
        == 1
    )

    assert (
        benign["block_false_positives"]
        == 1
    )

    assert (
        benign["monitor_benign_blocks"]
        == 0
    )

    assert (
        benign["block_benign_blocks"]
        == 0
    )