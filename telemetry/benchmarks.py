import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_jsonl_events(input_path: str) -> List[Dict[str, Any]]:
    path = Path(input_path)

    if not path.exists():
        raise FileNotFoundError(f"Telemetry file not found: {input_path}")

    events = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number} of {input_path}: {exc}"
                ) from exc

    return events


def safe_percent(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0

    return round((numerator / denominator) * 100, 2)


def get_bool(
    event: Dict[str, Any],
    section: str,
    key: str,
    default: bool = False,
) -> bool:
    return bool(event.get(section, {}).get(key, default))


def get_attack_succeeded(event: Dict[str, Any]) -> bool:
    result_value = event.get("result", {}).get("attack_succeeded")

    if result_value is not None:
        return bool(result_value)

    return bool(event.get("attack", {}).get("succeeded", False))


def get_defense_detected(event: Dict[str, Any]) -> bool:
    result_value = event.get("result", {}).get("defense_detected")

    if result_value is not None:
        return bool(result_value)

    return bool(event.get("defense", {}).get("detected", False))


def get_blocked(event: Dict[str, Any]) -> bool:
    result_value = event.get("result", {}).get("blocked")

    if result_value is not None:
        return bool(result_value)

    return bool(event.get("defense", {}).get("blocked", False))


def get_error(event: Dict[str, Any]) -> bool:
    result_value = event.get("result", {}).get("error")

    if result_value is not None:
        return bool(result_value)

    return event.get("event", {}).get("status") == "error"


def get_detector_names(event: Dict[str, Any]) -> List[str]:
    defense = event.get("defense", {})

    detector_names = defense.get("detector_names")

    if isinstance(detector_names, list):
        return [
            str(detector_name)
            for detector_name in detector_names
            if detector_name
        ]

    detection_mechanism = defense.get("detection_mechanism")

    if isinstance(detection_mechanism, str):
        return [
            item.strip()
            for item in detection_mechanism.split(",")
            if item.strip()
        ]

    return []


def calculate_benchmark_metrics(
    events: List[Dict[str, Any]],
    campaign_id: Optional[str] = None,
) -> Dict[str, Any]:
    if campaign_id:
        events = [
            event
            for event in events
            if event.get("campaign_id") == campaign_id
        ]

    total_events = len(events)

    attack_success_count = 0
    attack_failure_count = 0
    defense_detected_count = 0
    defense_missed_count = 0
    blocked_count = 0
    error_count = 0

    successful_attack_detected_count = 0
    successful_attack_missed_count = 0
    failed_attack_detected_count = 0
    failed_attack_not_detected_count = 0

    successful_attack_blocked_count = 0
    successful_attack_not_blocked_count = 0

    detector_counter = Counter()
    attack_family_counter = Counter()
    attack_severity_counter = Counter()
    target_counter = Counter()

    mutation_chain_stats = defaultdict(
        lambda: {
            "total": 0,
            "attack_successes": 0,
            "defense_detections": 0,
            "blocked": 0,
        }
    )

    per_attack_results = []

    for event in events:
        attack = event.get("attack", {})
        mutation = event.get("mutation", {})
        target = event.get("target", {})

        attack_id = attack.get("id") or attack.get("attack_id") or "unknown"
        attack_family = attack.get("family", "unknown")
        attack_severity = attack.get("severity", "unknown")
        target_name = target.get("name", "unknown")

        attack_succeeded = get_attack_succeeded(event)
        defense_detected = get_defense_detected(event)
        blocked = get_blocked(event)
        has_error = get_error(event)

        if attack_succeeded:
            attack_success_count += 1
        else:
            attack_failure_count += 1

        if defense_detected:
            defense_detected_count += 1
        else:
            defense_missed_count += 1

        if blocked:
            blocked_count += 1

        if has_error:
            error_count += 1

        if attack_succeeded and defense_detected:
            successful_attack_detected_count += 1

        if attack_succeeded and not defense_detected:
            successful_attack_missed_count += 1

        if not attack_succeeded and defense_detected:
            failed_attack_detected_count += 1

        if not attack_succeeded and not defense_detected:
            failed_attack_not_detected_count += 1

        if attack_succeeded and blocked:
            successful_attack_blocked_count += 1

        if attack_succeeded and not blocked:
            successful_attack_not_blocked_count += 1

        for detector_name in get_detector_names(event):
            detector_counter[detector_name] += 1

        attack_family_counter[attack_family] += 1
        attack_severity_counter[attack_severity] += 1
        target_counter[target_name] += 1

        mutation_chain = mutation.get("chain", [])

        if mutation_chain:
            mutation_chain_name = " -> ".join(mutation_chain)
        else:
            mutation_chain_name = "none"

        mutation_chain_stats[mutation_chain_name]["total"] += 1

        if attack_succeeded:
            mutation_chain_stats[mutation_chain_name]["attack_successes"] += 1

        if defense_detected:
            mutation_chain_stats[mutation_chain_name]["defense_detections"] += 1

        if blocked:
            mutation_chain_stats[mutation_chain_name]["blocked"] += 1

        per_attack_results.append(
            {
                "attack_id": attack_id,
                "family": attack_family,
                "severity": attack_severity,
                "mutation_chain": mutation_chain,
                "attack_succeeded": attack_succeeded,
                "defense_detected": defense_detected,
                "blocked": blocked,
                "detection_mechanism": event.get("defense", {}).get(
                    "detection_mechanism"
                ),
                "latency_ms": event.get("performance", {}).get("latency_ms"),
            }
        )

    mutation_chain_summary = {}

    for chain_name, stats in mutation_chain_stats.items():
        total = stats["total"]

        mutation_chain_summary[chain_name] = {
            **stats,
            "attack_success_rate": safe_percent(
                stats["attack_successes"],
                total,
            ),
            "defense_detection_rate": safe_percent(
                stats["defense_detections"],
                total,
            ),
            "block_rate": safe_percent(
                stats["blocked"],
                total,
            ),
        }

    return {
        "campaign_id_filter": campaign_id,
        "total_events": total_events,
        "summary": {
            "attack_success_count": attack_success_count,
            "attack_failure_count": attack_failure_count,
            "defense_detected_count": defense_detected_count,
            "defense_missed_count": defense_missed_count,
            "blocked_count": blocked_count,
            "error_count": error_count,
            "attack_success_rate": safe_percent(
                attack_success_count,
                total_events,
            ),
            "defense_detection_rate": safe_percent(
                defense_detected_count,
                total_events,
            ),
            "block_rate": safe_percent(
                blocked_count,
                total_events,
            ),
            "error_rate": safe_percent(
                error_count,
                total_events,
            ),
        },
        "outcome_matrix": {
            "attack_succeeded_and_detected": successful_attack_detected_count,
            "attack_succeeded_and_missed": successful_attack_missed_count,
            "attack_failed_and_detected": failed_attack_detected_count,
            "attack_failed_and_not_detected": failed_attack_not_detected_count,
        },
        "bypass_metrics": {
            "successful_attacks_blocked": successful_attack_blocked_count,
            "successful_attacks_not_blocked": successful_attack_not_blocked_count,
            "successful_attack_non_block_rate": safe_percent(
                successful_attack_not_blocked_count,
                attack_success_count,
            ),
            "critical_miss_rate": safe_percent(
                successful_attack_missed_count,
                total_events,
            ),
        },
        "detectors": {
            "counts": dict(detector_counter.most_common()),
            "top_5": detector_counter.most_common(5),
        },
        "attack_families": dict(attack_family_counter.most_common()),
        "attack_severities": dict(attack_severity_counter.most_common()),
        "targets": dict(target_counter.most_common()),
        "mutation_chains": mutation_chain_summary,
        "per_attack_results": per_attack_results,
    }


def format_benchmark_report(metrics: Dict[str, Any]) -> str:
    summary = metrics["summary"]
    outcome_matrix = metrics["outcome_matrix"]
    bypass_metrics = metrics["bypass_metrics"]

    lines = []

    lines.append("# LLM Security Benchmark Report")
    lines.append("")

    if metrics.get("campaign_id_filter"):
        lines.append(f"Campaign ID: {metrics['campaign_id_filter']}")
    else:
        lines.append("Campaign ID: all campaigns in file")

    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"Total events: {metrics['total_events']}")
    lines.append(
        f"Attack successes: {summary['attack_success_count']} "
        f"({summary['attack_success_rate']}%)"
    )
    lines.append(
        f"Defense detections: {summary['defense_detected_count']} "
        f"({summary['defense_detection_rate']}%)"
    )
    lines.append(
        f"Blocked requests: {summary['blocked_count']} "
        f"({summary['block_rate']}%)"
    )
    lines.append(
        f"Errors: {summary['error_count']} "
        f"({summary['error_rate']}%)"
    )

    lines.append("")
    lines.append("## Outcome Matrix")
    lines.append("")
    lines.append(
        "Attack succeeded + defense detected: "
        f"{outcome_matrix['attack_succeeded_and_detected']}"
    )
    lines.append(
        "Attack succeeded + defense missed: "
        f"{outcome_matrix['attack_succeeded_and_missed']}"
    )
    lines.append(
        "Attack failed + defense detected: "
        f"{outcome_matrix['attack_failed_and_detected']}"
    )
    lines.append(
        "Attack failed + defense not detected: "
        f"{outcome_matrix['attack_failed_and_not_detected']}"
    )

    lines.append("")
    lines.append("## Bypass Metrics")
    lines.append("")
    lines.append(
        "Successful attacks not blocked: "
        f"{bypass_metrics['successful_attacks_not_blocked']}"
    )
    lines.append(
        "Successful attack non-block rate: "
        f"{bypass_metrics['successful_attack_non_block_rate']}%"
    )
    lines.append(
        "Critical miss rate: "
        f"{bypass_metrics['critical_miss_rate']}%"
    )

    lines.append("")
    lines.append("## Top Detectors")
    lines.append("")

    top_detectors = metrics["detectors"]["top_5"]

    if top_detectors:
        for detector_name, count in top_detectors:
            lines.append(f"- {detector_name}: {count}")
    else:
        lines.append("- No detectors fired.")

    lines.append("")
    lines.append("## Mutation Chain Effectiveness")
    lines.append("")

    mutation_chains = metrics["mutation_chains"]

    if mutation_chains:
        sorted_chains = sorted(
            mutation_chains.items(),
            key=lambda item: (
                item[1]["attack_success_rate"],
                item[1]["defense_detection_rate"],
            ),
            reverse=True,
        )

        for chain_name, stats in sorted_chains:
            lines.append(f"- {chain_name}")
            lines.append(f"  - Total: {stats['total']}")
            lines.append(
                f"  - Attack success rate: {stats['attack_success_rate']}%"
            )
            lines.append(
                f"  - Defense detection rate: {stats['defense_detection_rate']}%"
            )
            lines.append(f"  - Block rate: {stats['block_rate']}%")
    else:
        lines.append("- No mutation chain data available.")

    lines.append("")
    lines.append("## Per-Attack Results")
    lines.append("")

    for result in metrics["per_attack_results"]:
        lines.append(
            f"- {result['attack_id']}: "
            f"success={result['attack_succeeded']}, "
            f"detected={result['defense_detected']}, "
            f"blocked={result['blocked']}, "
            f"severity={result['severity']}"
        )

    return "\n".join(lines)


def write_json_output(
    metrics: Dict[str, Any],
    output_path: str,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2)


def write_report_output(
    report: str,
    output_path: str,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        file.write(report)
        file.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate benchmark metrics from LLM security telemetry."
    )

    parser.add_argument(
        "--input",
        default="telemetry/events.jsonl",
        help="Input telemetry JSONL file.",
    )

    parser.add_argument(
        "--campaign-id",
        default=None,
        help="Optional campaign_id filter.",
    )

    parser.add_argument(
        "--json-output",
        default=None,
        help="Optional path to write benchmark metrics as JSON.",
    )

    parser.add_argument(
        "--report-output",
        default=None,
        help="Optional path to write benchmark report as Markdown.",
    )

    args = parser.parse_args()

    events = load_jsonl_events(args.input)

    metrics = calculate_benchmark_metrics(
        events=events,
        campaign_id=args.campaign_id,
    )

    report = format_benchmark_report(metrics)

    print(report)

    if args.json_output:
        write_json_output(
            metrics=metrics,
            output_path=args.json_output,
        )

    if args.report_output:
        write_report_output(
            report=report,
            output_path=args.report_output,
        )


if __name__ == "__main__":
    main()