from telemetry.benchmarks import (
    calculate_benchmark_metrics,
    format_benchmark_report,
)


def test_calculate_benchmark_metrics_counts_outcomes():
    events = [
        {
            "campaign_id": "campaign-1",
            "attack": {
                "id": "ATTACK-1",
                "family": "prompt_injection",
                "severity": "high",
            },
            "mutation": {
                "chain": ["json", "xml"],
            },
            "target": {
                "name": "local_defense_pipeline",
            },
            "defense": {
                "detected": True,
                "blocked": False,
                "detector_names": ["input_firewall:structured_instruction_markers"],
                "detection_mechanism": "input_firewall:structured_instruction_markers",
            },
            "result": {
                "attack_succeeded": True,
                "defense_detected": True,
                "blocked": False,
                "error": False,
            },
            "performance": {
                "latency_ms": 1,
            },
        },
        {
            "campaign_id": "campaign-1",
            "attack": {
                "id": "ATTACK-2",
                "family": "data_exfiltration",
                "severity": "critical",
            },
            "mutation": {
                "chain": ["base64"],
            },
            "target": {
                "name": "local_defense_pipeline",
            },
            "defense": {
                "detected": False,
                "blocked": False,
                "detector_names": [],
                "detection_mechanism": None,
            },
            "result": {
                "attack_succeeded": True,
                "defense_detected": False,
                "blocked": False,
                "error": False,
            },
            "performance": {
                "latency_ms": 1,
            },
        },
        {
            "campaign_id": "campaign-1",
            "attack": {
                "id": "ATTACK-3",
                "family": "tool_abuse",
                "severity": "high",
            },
            "mutation": {
                "chain": ["xml"],
            },
            "target": {
                "name": "local_defense_pipeline",
            },
            "defense": {
                "detected": True,
                "blocked": True,
                "detector_names": ["input_firewall:tool_abuse"],
                "detection_mechanism": "input_firewall:tool_abuse",
            },
            "result": {
                "attack_succeeded": False,
                "defense_detected": True,
                "blocked": True,
                "error": False,
            },
            "performance": {
                "latency_ms": 1,
            },
        },
    ]

    metrics = calculate_benchmark_metrics(events)

    assert metrics["total_events"] == 3
    assert metrics["summary"]["attack_success_count"] == 2
    assert metrics["summary"]["defense_detected_count"] == 2
    assert metrics["summary"]["blocked_count"] == 1

    assert metrics["outcome_matrix"]["attack_succeeded_and_detected"] == 1
    assert metrics["outcome_matrix"]["attack_succeeded_and_missed"] == 1
    assert metrics["outcome_matrix"]["attack_failed_and_detected"] == 1
    assert metrics["outcome_matrix"]["attack_failed_and_not_detected"] == 0

    assert metrics["bypass_metrics"]["successful_attacks_not_blocked"] == 2


def test_calculate_benchmark_metrics_filters_by_campaign_id():
    events = [
        {
            "campaign_id": "campaign-1",
            "attack": {"id": "ATTACK-1"},
            "mutation": {"chain": []},
            "target": {"name": "local"},
            "defense": {"detected": True, "blocked": False},
            "result": {
                "attack_succeeded": True,
                "defense_detected": True,
                "blocked": False,
                "error": False,
            },
        },
        {
            "campaign_id": "campaign-2",
            "attack": {"id": "ATTACK-2"},
            "mutation": {"chain": []},
            "target": {"name": "local"},
            "defense": {"detected": False, "blocked": False},
            "result": {
                "attack_succeeded": False,
                "defense_detected": False,
                "blocked": False,
                "error": False,
            },
        },
    ]

    metrics = calculate_benchmark_metrics(
        events=events,
        campaign_id="campaign-1",
    )

    assert metrics["total_events"] == 1
    assert metrics["summary"]["attack_success_count"] == 1


def test_format_benchmark_report_contains_main_sections():
    events = [
        {
            "campaign_id": "campaign-1",
            "attack": {
                "id": "ATTACK-1",
                "family": "prompt_injection",
                "severity": "high",
            },
            "mutation": {
                "chain": ["json"],
            },
            "target": {
                "name": "local",
            },
            "defense": {
                "detected": True,
                "blocked": False,
                "detector_names": ["input_firewall:structured_instruction_markers"],
            },
            "result": {
                "attack_succeeded": False,
                "defense_detected": True,
                "blocked": False,
                "error": False,
            },
            "performance": {
                "latency_ms": 1,
            },
        }
    ]

    metrics = calculate_benchmark_metrics(events)
    report = format_benchmark_report(metrics)

    assert "# LLM Security Benchmark Report" in report
    assert "## Summary" in report
    assert "## Outcome Matrix" in report
    assert "## Mutation Chain Effectiveness" in report