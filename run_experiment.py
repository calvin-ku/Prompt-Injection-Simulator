"""Run one reproducible monitor-versus-block security experiment."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "telemetry" / "experiments"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_experiment_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"exp-{timestamp}-{uuid4().hex[:8]}"


def read_env_value(path: Path, key: str) -> str | None:
    if not path.exists():
        return None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        current_key, value = line.split("=", 1)

        if current_key.strip() != key:
            continue

        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]

        return value

    return None


def run_logged_command(
    command: list[str],
    log_path: Path,
    environment: dict[str, str] | None = None,
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("w", encoding="utf-8") as log_file:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=environment,
            check=False,
        )

    if result.returncode == 0:
        return

    tail = log_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines()[-40:]

    raise RuntimeError(
        "Campaign command failed with exit code "
        f"{result.returncode}. See {log_path}.\n"
        + "\n".join(tail)
    )


def build_campaign_command(
    args: argparse.Namespace,
    firewall_mode: str,
    output_path: Path,
    experiment_id: str,
) -> list[str]:
    """Forward every run_campaign.py option that affects benchmark output."""
    command = [
        sys.executable,
        str(PROJECT_ROOT / "run_campaign.py"),
        "--attack-catalog",
        args.attack_catalog,
        "--owasp-mapping",
        args.owasp_mapping,
        "--atlas-mapping",
        args.atlas_mapping,
        "--benign-catalog",
        args.benign_catalog,
        "--seed",
        str(args.seed),
        "--random-depth",
        str(args.random_depth),
        "--variants-per-attack",
        str(args.variants_per_attack),
        "--target",
        args.target,
        "--firewall-mode",
        firewall_mode,
        "--target-mode",
        args.target_mode,
        "--environment",
        args.environment,
        "--experiment-id",
        experiment_id,
        "--output",
        str(output_path),
    ]

    if args.attack:
        command.extend(["--attack", args.attack])

    if args.mutations:
        command.extend(["--mutations", args.mutations])

    if args.include_benign:
        command.append("--include-benign")
    elif args.benign_only:
        command.append("--benign-only")

    return command


def event_type(event: dict[str, Any]) -> str | None:
    nested_event = event.get("event")

    if isinstance(nested_event, dict) and nested_event.get("type"):
        return str(nested_event["type"])

    if event.get("event_type"):
        return str(event["event_type"])

    return None


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON in {path} line {line_number}: {exc}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"Expected a JSON object in {path} line {line_number}."
                )

            yield event


def nested_value(event: dict[str, Any], *path: str) -> Any:
    current: Any = event

    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current


def attack_identity(event: dict[str, Any]) -> tuple[str, int]:
    attack_id = (
        nested_value(event, "attack", "id")
        or nested_value(event, "attack", "attack_id")
        or event.get("attack_id")
    )
    variant_index = (
        nested_value(event, "attack", "variant_index")
        or nested_value(event, "reproducibility", "variant_index")
        or event.get("variant_index")
    )

    if attack_id is None or variant_index is None:
        raise ValueError(
            "Adversarial telemetry is missing attack.id or variant_index."
        )

    return str(attack_id), int(variant_index)


def variant_signature(event: dict[str, Any]) -> tuple[Any, Any, Any]:
    """Fields that must be identical for a monitor/block variant pair."""
    payload = (
        nested_value(event, "mutation", "mutated_payload")
        or nested_value(event, "mutation", "payload")
        or nested_value(event, "request_response", "request")
        or event.get("payload")
    )
    variant_seed = (
        nested_value(event, "reproducibility", "variant_seed")
        or nested_value(event, "reproducibility", "random_seed")
        or event.get("variant_seed")
    )
    generation_attempt = (
        nested_value(event, "reproducibility", "generation_attempt")
        or event.get("generation_attempt")
    )
    return payload, variant_seed, generation_attempt


def load_attack_map(path: Path) -> dict[tuple[str, int], dict[str, Any]]:
    attacks: dict[tuple[str, int], dict[str, Any]] = {}

    for event in iter_jsonl(path):
        if event_type(event) != "adversarial_test":
            continue

        key = attack_identity(event)

        if key in attacks:
            raise ValueError(f"Duplicate attack variant in {path}: {key}")

        attacks[key] = event

    return attacks


def validate_paired_campaigns(
    monitor_path: Path,
    block_path: Path,
    experiment_id: str,
) -> int:
    monitor = load_attack_map(monitor_path)
    block = load_attack_map(block_path)

    if set(monitor) != set(block):
        raise ValueError(
            "Monitor and block attack variants do not match. "
            f"Monitor-only: {sorted(set(monitor) - set(block))[:10]}; "
            f"block-only: {sorted(set(block) - set(monitor))[:10]}."
        )

    mismatches = [
        key
        for key in monitor
        if variant_signature(monitor[key]) != variant_signature(block[key])
    ]

    if mismatches:
        raise ValueError(
            "Monitor/block payload or reproducibility mismatch for "
            f"{len(mismatches)} variants: {sorted(mismatches)[:10]}."
        )

    for path in (monitor_path, block_path):
        for event in iter_jsonl(path):
            if event.get("experiment_id") != experiment_id:
                raise ValueError(
                    f"Event in {path} is missing experiment_id {experiment_id}."
                )

    return len(monitor)


def summarize_events(path: Path) -> dict[str, int]:
    counts = {"total_events": 0, "adversarial_events": 0, "benign_events": 0}

    for event in iter_jsonl(path):
        counts["total_events"] += 1

        if event_type(event) == "adversarial_test":
            counts["adversarial_events"] += 1
        elif event_type(event) == "benign_test":
            counts["benign_events"] += 1

    return counts


def combine_jsonl(paths: list[Path], output_path: Path) -> None:
    with output_path.open("wb") as output_file:
        for path in paths:
            with path.open("rb") as input_file:
                shutil.copyfileobj(input_file, output_file)


def write_experiment_summary(
    path: Path,
    args: argparse.Namespace,
    experiment_id: str,
    monitor: dict[str, int],
    block: dict[str, int],
    paired_attack_variants: int,
) -> None:
    summary = {
        "event_id": str(uuid4()),
        "experiment_id": experiment_id,
        "timestamp": utc_now_iso(),
        "schema_version": "1.0.0",
        "event": {
            "kind": "event",
            "category": "llm_security",
            "type": "experiment_summary",
            "outcome": "success",
            "status": "completed",
        },
        "experiment": {
            "id": experiment_id,
            "status": "completed",
            "paired": True,
            "seed": args.seed,
            "variants_per_attack": args.variants_per_attack,
            "paired_attack_variants": paired_attack_variants,
            "target": args.target,
            "target_mode": args.target_mode,
            "monitor": monitor,
            "block": block,
            "total_execution_events": (
                monitor["total_events"] + block["total_events"]
            ),
        },
    }
    path.write_text(json.dumps(summary, separators=(",", ":")) + "\n", encoding="utf-8")


def get_splunk_environment() -> dict[str, str]:
    environment = dict(os.environ)
    token = environment.get("SPLUNK_HEC_TOKEN") or read_env_value(
        PROJECT_ROOT / ".env.splunk",
        "SPLUNK_HEC_TOKEN",
    )

    if not token:
        raise RuntimeError(
            "Set SPLUNK_HEC_TOKEN or add it to .env.splunk before "
            "using --send-to-splunk."
        )

    environment["SPLUNK_HEC_TOKEN"] = token
    return environment


def send_to_splunk(
    input_path: Path,
    args: argparse.Namespace,
    log_path: Path,
    environment: dict[str, str],
) -> None:
    command = [
        sys.executable,
        "-m",
        "telemetry.splunk_hec",
        "--input",
        str(input_path),
        "--url",
        args.splunk_url,
        "--batch-size",
        str(args.batch_size),
    ]

    if args.insecure:
        command.append("--insecure")

    run_logged_command(command, log_path, environment)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a reproducible paired monitor/block benchmark."
    )
    parser.add_argument("--attack-catalog", default="attack_catalog/attack_catalog.json")
    parser.add_argument("--owasp-mapping", default="attack_catalog/owasp_mapping.json")
    parser.add_argument("--atlas-mapping", default="attack_catalog/mitre_atlas_mapping.json")
    parser.add_argument("--benign-catalog", default="attack_catalog/benign_samples.json")
    parser.add_argument("--attack", default=None)
    parser.add_argument("--mutations", default=None)
    parser.add_argument("--seed", type=int, default=12345)
    parser.add_argument("--random-depth", type=int, default=3)
    parser.add_argument("--variants-per-attack", type=int, default=100)
    parser.add_argument(
        "--target",
        choices=["local"],
        default="local",
        help="Paired experiments require the local target and its firewall.",
    )
    parser.add_argument(
        "--target-mode",
        choices=["safe", "echo", "vulnerable"],
        default="vulnerable",
    )
    parser.add_argument("--environment", default="local")
    traffic_group = parser.add_mutually_exclusive_group()
    traffic_group.add_argument("--include-benign", action="store_true")
    traffic_group.add_argument("--benign-only", action="store_true")
    parser.add_argument("--experiment-id", default=None)
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    parser.add_argument("--send-to-splunk", action="store_true")
    parser.add_argument(
        "--splunk-url",
        default="https://localhost:8088/services/collector/event",
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    if args.variants_per_attack < 1:
        parser.error("--variants-per-attack must be at least 1.")
    if args.random_depth < 1:
        parser.error("--random-depth must be at least 1.")
    if args.benign_only and args.attack:
        parser.error("--attack cannot be combined with --benign-only.")

    return args


def main() -> None:
    args = parse_args()
    experiment_id = args.experiment_id or make_experiment_id()
    output_root = Path(args.output_root)

    if not output_root.is_absolute():
        output_root = PROJECT_ROOT / output_root

    experiment_dir = output_root / experiment_id
    experiment_dir.mkdir(parents=True, exist_ok=False)
    monitor_path = experiment_dir / "monitor.jsonl"
    block_path = experiment_dir / "block.jsonl"
    summary_path = experiment_dir / "experiment_summary.jsonl"

    print(f"Experiment ID: {experiment_id}")
    print("[1/5] Running monitor campaign...")
    run_logged_command(
        build_campaign_command(args, "monitor", monitor_path, experiment_id),
        experiment_dir / "monitor-run.log",
    )
    monitor = summarize_events(monitor_path)

    print("[2/5] Running block campaign...")
    run_logged_command(
        build_campaign_command(args, "block", block_path, experiment_id),
        experiment_dir / "block-run.log",
    )
    block = summarize_events(block_path)

    print("[3/5] Validating monitor/block pairing...")
    paired_attack_variants = validate_paired_campaigns(
        monitor_path,
        block_path,
        experiment_id,
    )
    combine_jsonl([monitor_path, block_path], experiment_dir / "combined.jsonl")
    write_experiment_summary(
        summary_path,
        args,
        experiment_id,
        monitor,
        block,
        paired_attack_variants,
    )
    print(f"Validated {paired_attack_variants} paired attack variants.")
    print("[4/5] Experiment metadata written.")

    if args.send_to_splunk:
        print("[5/5] Sending completed experiment to Splunk...")
        environment = get_splunk_environment()
        send_to_splunk(monitor_path, args, experiment_dir / "splunk-monitor.log", environment)
        send_to_splunk(block_path, args, experiment_dir / "splunk-block.log", environment)
        send_to_splunk(summary_path, args, experiment_dir / "splunk-summary.log", environment)
    else:
        print("[5/5] Splunk export skipped.")

    print(json.dumps({
        "experiment_id": experiment_id,
        "status": "completed",
        "paired_attack_variants": paired_attack_variants,
        "monitor": monitor,
        "block": block,
        "output_directory": str(experiment_dir),
        "splunk_exported": args.send_to_splunk,
    }, indent=2))


if __name__ == "__main__":
    main()