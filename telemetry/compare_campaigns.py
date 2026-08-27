import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple


def load_jsonl(
    path: str,
) -> List[Dict[str, Any]]:
    file_path = Path(path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Telemetry file not found: {path}"
        )

    events = []

    with file_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line "
                    f"{line_number} of {path}: {exc}"
                ) from exc

    return events


def get_event_type(
    event: Dict[str, Any],
) -> str:
    event_type = (
        event.get(
            "event",
            {},
        ).get("type")
    )

    if event_type:
        return event_type

    if (
        "sample" in event
        and "attack" not in event
    ):
        return "benign_test"

    return "adversarial_test"


def get_attack_events(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return [
        event
        for event in events
        if get_event_type(event)
        == "adversarial_test"
    ]


def get_benign_events(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return [
        event
        for event in events
        if get_event_type(event)
        == "benign_test"
    ]


def get_attack_key(
    event: Dict[str, Any],
) -> Tuple[str, Any]:
    attack = event.get(
        "attack",
        {},
    )

    attack_id = (
        attack.get("id")
        or attack.get("attack_id")
        or "unknown"
    )

    variant_index = (
        attack.get(
            "variant_index"
        )
    )

    return (
        attack_id,
        variant_index,
    )


def get_payload(
    event: Dict[str, Any],
) -> Any:
    return (
        event.get(
            "mutation",
            {},
        ).get(
            "mutated_payload"
        )
    )


def get_variant_seed(
    event: Dict[str, Any],
) -> Any:
    return (
        event.get(
            "reproducibility",
            {},
        ).get(
            "variant_seed"
        )
    )


def get_attack_succeeded(
    event: Dict[str, Any],
) -> bool:
    return bool(
        event.get(
            "result",
            {},
        ).get(
            "attack_succeeded",
            False,
        )
    )


def get_blocked(
    event: Dict[str, Any],
) -> bool:
    return bool(
        event.get(
            "result",
            {},
        ).get(
            "blocked",
            False,
        )
    )


def get_defense_detected(
    event: Dict[str, Any],
) -> bool:
    return bool(
        event.get(
            "result",
            {},
        ).get(
            "defense_detected",
            False,
        )
    )


def get_false_positive(
    event: Dict[str, Any],
) -> bool:
    result = event.get(
        "result",
        {},
    )

    if (
        "false_positive"
        in result
    ):
        return bool(
            result[
                "false_positive"
            ]
        )

    return get_defense_detected(
        event
    )


def calculate_comparison(
    monitor_events: List[Dict[str, Any]],
    block_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    monitor_attacks = (
        get_attack_events(
            monitor_events
        )
    )

    block_attacks = (
        get_attack_events(
            block_events
        )
    )

    monitor_benign = (
        get_benign_events(
            monitor_events
        )
    )

    block_benign = (
        get_benign_events(
            block_events
        )
    )

    monitor_by_key = {
        get_attack_key(event): event
        for event in monitor_attacks
    }

    block_by_key = {
        get_attack_key(event): event
        for event in block_attacks
    }

    monitor_keys = set(
        monitor_by_key
    )

    block_keys = set(
        block_by_key
    )

    shared_keys = (
        monitor_keys
        & block_keys
    )

    monitor_only = (
        monitor_keys
        - block_keys
    )

    block_only = (
        block_keys
        - monitor_keys
    )

    payload_mismatches = 0
    seed_mismatches = 0

    monitor_successes = 0
    prevented_successes = 0
    unprevented_successes = 0

    monitor_detected = 0
    block_detected = 0

    total_block_events = 0

    per_attack = defaultdict(
        lambda: {
            "paired_variants": 0,
            "monitor_successes": 0,
            "block_successes": 0,
            "prevented_successes": 0,
            "unprevented_successes": 0,
            "monitor_detections": 0,
            "block_detections": 0,
            "block_events": 0,
        }
    )

    for key in sorted(
        shared_keys
    ):
        monitor_event = (
            monitor_by_key[
                key
            ]
        )

        block_event = (
            block_by_key[
                key
            ]
        )

        attack_id, _ = key

        if (
            get_payload(
                monitor_event
            )
            != get_payload(
                block_event
            )
        ):
            payload_mismatches += 1

        if (
            get_variant_seed(
                monitor_event
            )
            != get_variant_seed(
                block_event
            )
        ):
            seed_mismatches += 1

        monitor_success = (
            get_attack_succeeded(
                monitor_event
            )
        )

        block_success = (
            get_attack_succeeded(
                block_event
            )
        )

        monitor_detection = (
            get_defense_detected(
                monitor_event
            )
        )

        block_detection = (
            get_defense_detected(
                block_event
            )
        )

        block_event_blocked = (
            get_blocked(
                block_event
            )
        )

        stats = (
            per_attack[
                attack_id
            ]
        )

        stats[
            "paired_variants"
        ] += 1

        if monitor_detection:
            monitor_detected += 1

            stats[
                "monitor_detections"
            ] += 1

        if block_detection:
            block_detected += 1

            stats[
                "block_detections"
            ] += 1

        if block_event_blocked:
            total_block_events += 1

            stats[
                "block_events"
            ] += 1

        if monitor_success:
            monitor_successes += 1

            stats[
                "monitor_successes"
            ] += 1

        if block_success:
            stats[
                "block_successes"
            ] += 1

        if monitor_success:
            if (
                block_event_blocked
                and not block_success
            ):
                prevented_successes += 1

                stats[
                    "prevented_successes"
                ] += 1

            else:
                unprevented_successes += 1

                stats[
                    "unprevented_successes"
                ] += 1

    if monitor_successes:
        prevention_rate = round(
            (
                prevented_successes
                / monitor_successes
            )
            * 100,
            2,
        )
    else:
        prevention_rate = None

    per_attack_summary = {}

    for (
        attack_id,
        stats,
    ) in sorted(
        per_attack.items()
    ):
        monitor_attack_successes = (
            stats[
                "monitor_successes"
            ]
        )

        if monitor_attack_successes:
            attack_prevention_rate = round(
                (
                    stats[
                        "prevented_successes"
                    ]
                    / monitor_attack_successes
                )
                * 100,
                2,
            )
        else:
            attack_prevention_rate = None

        paired = (
            stats[
                "paired_variants"
            ]
        )

        monitor_detection_rate = (
            round(
                (
                    stats[
                        "monitor_detections"
                    ]
                    / paired
                )
                * 100,
                2,
            )
            if paired
            else 0.0
        )

        block_detection_rate = (
            round(
                (
                    stats[
                        "block_detections"
                    ]
                    / paired
                )
                * 100,
                2,
            )
            if paired
            else 0.0
        )

        block_rate = (
            round(
                (
                    stats[
                        "block_events"
                    ]
                    / paired
                )
                * 100,
                2,
            )
            if paired
            else 0.0
        )

        per_attack_summary[
            attack_id
        ] = {
            **stats,
            "prevention_rate": (
                attack_prevention_rate
            ),
            "monitor_detection_rate": (
                monitor_detection_rate
            ),
            "block_detection_rate": (
                block_detection_rate
            ),
            "block_rate": (
                block_rate
            ),
        }

    monitor_fp = sum(
        1
        for event in monitor_benign
        if get_false_positive(
            event
        )
    )

    block_fp = sum(
        1
        for event in block_benign
        if get_false_positive(
            event
        )
    )

    monitor_benign_blocks = sum(
        1
        for event in monitor_benign
        if get_blocked(
            event
        )
    )

    block_benign_blocks = sum(
        1
        for event in block_benign
        if get_blocked(
            event
        )
    )

    return {
        "pairing": {
            "monitor_attack_events": (
                len(
                    monitor_attacks
                )
            ),
            "block_attack_events": (
                len(
                    block_attacks
                )
            ),
            "paired_variants": (
                len(
                    shared_keys
                )
            ),
            "monitor_only_variants": (
                len(
                    monitor_only
                )
            ),
            "block_only_variants": (
                len(
                    block_only
                )
            ),
            "payload_mismatches": (
                payload_mismatches
            ),
            "seed_mismatches": (
                seed_mismatches
            ),
        },

        "prevention": {
            "monitor_successes": (
                monitor_successes
            ),
            "prevented_successes": (
                prevented_successes
            ),
            "unprevented_successes": (
                unprevented_successes
            ),
            "prevention_rate": (
                prevention_rate
            ),
            "block_events": (
                total_block_events
            ),
        },

        "detection": {
            "monitor_detections": (
                monitor_detected
            ),
            "block_detections": (
                block_detected
            ),
        },

        "benign": {
            "monitor_samples": (
                len(
                    monitor_benign
                )
            ),
            "block_samples": (
                len(
                    block_benign
                )
            ),
            "monitor_false_positives": (
                monitor_fp
            ),
            "block_false_positives": (
                block_fp
            ),
            "monitor_benign_blocks": (
                monitor_benign_blocks
            ),
            "block_benign_blocks": (
                block_benign_blocks
            ),
        },

        "per_attack": (
            per_attack_summary
        ),
    }


def format_report(
    comparison: Dict[str, Any],
) -> str:
    pairing = (
        comparison[
            "pairing"
        ]
    )

    prevention = (
        comparison[
            "prevention"
        ]
    )

    detection = (
        comparison[
            "detection"
        ]
    )

    benign = (
        comparison[
            "benign"
        ]
    )

    lines = []

    lines.append(
        "# LLM Defense Campaign Comparison"
    )

    lines.append("")
    lines.append(
        "## Pairing Validation"
    )
    lines.append("")

    lines.append(
        "Monitor attack events: "
        f"{pairing['monitor_attack_events']}"
    )

    lines.append(
        "Block attack events: "
        f"{pairing['block_attack_events']}"
    )

    lines.append(
        "Paired variants: "
        f"{pairing['paired_variants']}"
    )

    lines.append(
        "Monitor-only variants: "
        f"{pairing['monitor_only_variants']}"
    )

    lines.append(
        "Block-only variants: "
        f"{pairing['block_only_variants']}"
    )

    lines.append(
        "Payload mismatches: "
        f"{pairing['payload_mismatches']}"
    )

    lines.append(
        "Variant-seed mismatches: "
        f"{pairing['seed_mismatches']}"
    )

    lines.append("")
    lines.append(
        "## Prevention"
    )
    lines.append("")

    lines.append(
        "Monitor successes: "
        f"{prevention['monitor_successes']}"
    )

    lines.append(
        "Prevented successes: "
        f"{prevention['prevented_successes']}"
    )

    lines.append(
        "Unprevented successes: "
        f"{prevention['unprevented_successes']}"
    )

    if (
        prevention[
            "prevention_rate"
        ]
        is None
    ):
        lines.append(
            "Prevention rate: N/A"
        )
    else:
        lines.append(
            "Prevention rate: "
            f"{prevention['prevention_rate']}%"
        )

    lines.append(
        "Total block events: "
        f"{prevention['block_events']}"
    )

    lines.append("")
    lines.append(
        "## Detection"
    )
    lines.append("")

    lines.append(
        "Monitor detections: "
        f"{detection['monitor_detections']}"
    )

    lines.append(
        "Block detections: "
        f"{detection['block_detections']}"
    )

    lines.append("")
    lines.append(
        "## Benign Impact"
    )
    lines.append("")

    lines.append(
        "Monitor benign samples: "
        f"{benign['monitor_samples']}"
    )

    lines.append(
        "Block benign samples: "
        f"{benign['block_samples']}"
    )

    lines.append(
        "Monitor false positives: "
        f"{benign['monitor_false_positives']}"
    )

    lines.append(
        "Block false positives: "
        f"{benign['block_false_positives']}"
    )

    lines.append(
        "Monitor benign blocks: "
        f"{benign['monitor_benign_blocks']}"
    )

    lines.append(
        "Block benign blocks: "
        f"{benign['block_benign_blocks']}"
    )

    lines.append("")
    lines.append(
        "## Per-Attack Comparison"
    )
    lines.append("")

    for (
        attack_id,
        stats,
    ) in comparison[
        "per_attack"
    ].items():
        lines.append(
            f"### {attack_id}"
        )
        lines.append("")

        lines.append(
            "Paired variants: "
            f"{stats['paired_variants']}"
        )

        lines.append(
            "Monitor successes: "
            f"{stats['monitor_successes']}"
        )

        lines.append(
            "Block successes: "
            f"{stats['block_successes']}"
        )

        lines.append(
            "Prevented successes: "
            f"{stats['prevented_successes']}"
        )

        lines.append(
            "Unprevented successes: "
            f"{stats['unprevented_successes']}"
        )

        if (
            stats[
                "prevention_rate"
            ]
            is None
        ):
            lines.append(
                "Prevention rate: N/A"
            )
        else:
            lines.append(
                "Prevention rate: "
                f"{stats['prevention_rate']}%"
            )

        lines.append(
            "Monitor detection rate: "
            f"{stats['monitor_detection_rate']}%"
        )

        lines.append(
            "Block detection rate: "
            f"{stats['block_detection_rate']}%"
        )

        lines.append(
            "Block rate: "
            f"{stats['block_rate']}%"
        )

        lines.append("")

    return "\n".join(
        lines
    )


def write_json(
    data: Dict[str, Any],
    output_path: str,
) -> None:
    path = Path(
        output_path
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
        )


def write_report(
    report: str,
    output_path: str,
) -> None:
    path = Path(
        output_path
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            report
        )

        file.write(
            "\n"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Compare reproducibly paired monitor "
            "and block LLM security campaigns."
        )
    )

    parser.add_argument(
        "--monitor",
        required=True,
        help=(
            "Monitor-mode telemetry JSONL."
        ),
    )

    parser.add_argument(
        "--block",
        required=True,
        help=(
            "Block-mode telemetry JSONL."
        ),
    )

    parser.add_argument(
        "--json-output",
        default=(
            "telemetry/"
            "campaign_comparison.json"
        ),
        help=(
            "Comparison JSON output path."
        ),
    )

    parser.add_argument(
        "--report-output",
        default=(
            "telemetry/"
            "campaign_comparison.md"
        ),
        help=(
            "Comparison Markdown output path."
        ),
    )

    args = parser.parse_args()

    monitor_events = load_jsonl(
        args.monitor
    )

    block_events = load_jsonl(
        args.block
    )

    comparison = (
        calculate_comparison(
            monitor_events=(
                monitor_events
            ),
            block_events=(
                block_events
            ),
        )
    )

    report = format_report(
        comparison
    )

    print(
        report
    )

    write_json(
        comparison,
        args.json_output,
    )

    write_report(
        report,
        args.report_output,
    )


if __name__ == "__main__":
    main()