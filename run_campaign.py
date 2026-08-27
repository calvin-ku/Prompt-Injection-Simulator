import argparse
import json
from uuid import uuid4

from attack_engine.benign import BenignRunner
from attack_engine.generator import AttackEngine
from attack_engine.mutators import PayloadMutator
from attack_engine.orchestrator import CampaignOrchestrator
from attack_engine.target import build_target_from_name
from attack_engine.validator import CatalogValidator


def parse_mutations(raw: str):
    if not raw:
        return None

    return [
        item.strip()
        for item in raw.split(",")
        if item.strip()
    ]


def load_benign_samples(path: str):
    with open(path, "r", encoding="utf-8") as file:
        samples = json.load(file)

    if not isinstance(samples, list):
        raise ValueError(
            "Benign sample catalog must contain a JSON list."
        )

    return samples


def print_attack_result(result, args):
    print(json.dumps({
        "event_type": "adversarial_test",
        "campaign_id": result.campaign_id,
        "event_id": result.event_id,
        "attack_id": result.attack_id,
        "owasp_id": result.owasp_id,
        "atlas_id": result.atlas_id,
        "mutation_chain": result.mutation_chain,
        "attack_succeeded": result.evaluation.succeeded,
        "defense_detected": result.target_response.detected,
        "blocked": result.target_response.blocked,
        "detection_mechanism": (
            result.target_response.detection_mechanism
        ),
        "latency_ms": result.target_response.latency_ms,
        "random_seed": args.seed,
        "target": args.target,
    }, indent=2))


def print_benign_result(result, args):
    telemetry = result.telemetry

    print(json.dumps({
        "event_type": "benign_test",
        "campaign_id": telemetry["campaign_id"],
        "event_id": telemetry["event_id"],
        "sample_id": result.sample_id,
        "category": result.category,
        "expected_result": result.expected_result,
        "false_positive": result.false_positive,
        "benign_blocked": result.benign_blocked,
        "defense_detected": result.target_response.detected,
        "blocked": result.target_response.blocked,
        "detection_mechanism": (
            result.target_response.detection_mechanism
        ),
        "latency_ms": result.target_response.latency_ms,
        "target": args.target,
    }, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run a reproducible LLM security benchmark campaign."
        )
    )

    parser.add_argument(
        "--attack-catalog",
        default="attack_catalog/attack_catalog.json",
    )

    parser.add_argument(
        "--owasp-mapping",
        default="attack_catalog/owasp_mapping.json",
    )

    parser.add_argument(
        "--atlas-mapping",
        default="attack_catalog/mitre_atlas_mapping.json",
    )

    parser.add_argument(
        "--benign-catalog",
        default="attack_catalog/benign_samples.json",
        help="Path to benign sample catalog.",
    )

    parser.add_argument(
        "--attack",
        help="Specific attack_id to run. If omitted, runs all attacks.",
    )

    parser.add_argument(
        "--mutations",
        default=None,
        help=(
            "Comma-separated mutation chain, "
            "e.g. base64,homoglyph,xml"
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=12345,
    )

    parser.add_argument(
        "--random-depth",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--target",
        choices=["mock", "local"],
        default="mock",
        help="Target backend to run benchmark traffic against.",
    )

    parser.add_argument(
        "--firewall-mode",
        choices=["block", "monitor"],
        default=None,
        help="Firewall mode for --target local.",
    )

    parser.add_argument(
        "--target-mode",
        choices=["safe", "echo", "vulnerable"],
        default=None,
        help="Local target app mode for --target local.",
    )

    parser.add_argument(
        "--environment",
        default="local",
        help="Environment label written into telemetry.",
    )

    parser.add_argument(
        "--output",
        default="telemetry/events.jsonl",
        help="Path to JSONL telemetry output.",
    )

    traffic_group = parser.add_mutually_exclusive_group()

    traffic_group.add_argument(
        "--include-benign",
        action="store_true",
        help=(
            "Run benign samples in addition to attack samples "
            "and include them in the same campaign."
        ),
    )

    traffic_group.add_argument(
        "--benign-only",
        action="store_true",
        help="Run only benign samples.",
    )

    args = parser.parse_args()

    if args.benign_only and args.attack:
        parser.error(
            "--attack cannot be combined with --benign-only."
        )

    campaign_id = str(uuid4())

    mutator = PayloadMutator(seed=args.seed)

    target = build_target_from_name(
        target_name=args.target,
        firewall_mode=args.firewall_mode,
        target_mode=args.target_mode,
        environment=args.environment,
    )

    engine = AttackEngine(
        target=target,
        mutator=mutator,
    )

    orchestrator = CampaignOrchestrator(engine)

    attack_results = []
    benign_results = []

    # ---------------------------------------------------------
    # Adversarial traffic
    # ---------------------------------------------------------

    if not args.benign_only:
        validator = CatalogValidator(
            mutator_names=set(mutator.registry.keys())
        )

        attacks, owasp_mapping, atlas_mapping = (
            validator.validate_all(
                attack_catalog_path=args.attack_catalog,
                owasp_mapping_path=args.owasp_mapping,
                atlas_mapping_path=args.atlas_mapping,
            )
        )

        mutations = parse_mutations(args.mutations)

        if args.attack:
            result = orchestrator.run_single_attack(
                attack_id=args.attack,
                attacks=attacks,
                owasp_mapping=owasp_mapping,
                atlas_mapping=atlas_mapping,
                seed=args.seed,
                mutations=mutations,
                random_depth=args.random_depth,
                campaign_id=campaign_id,
            )

            attack_results = [result]

        else:
            attack_results = orchestrator.run_campaign(
                attacks=attacks,
                owasp_mapping=owasp_mapping,
                atlas_mapping=atlas_mapping,
                seed=args.seed,
                mutations=mutations,
                random_depth=args.random_depth,
                campaign_id=campaign_id,
            )

    # ---------------------------------------------------------
    # Benign traffic
    # ---------------------------------------------------------

    if args.include_benign or args.benign_only:
        benign_samples = load_benign_samples(
            args.benign_catalog
        )

        benign_runner = BenignRunner(target)

        benign_results = orchestrator.run_benign_campaign(
            runner=benign_runner,
            samples=benign_samples,
            campaign_id=campaign_id,
        )

    # ---------------------------------------------------------
    # Combined telemetry
    # ---------------------------------------------------------

    all_results = attack_results + benign_results

    orchestrator.write_telemetry_jsonl(
        results=all_results,
        output_path=args.output,
    )

    # ---------------------------------------------------------
    # Console output
    # ---------------------------------------------------------

    for result in attack_results:
        print_attack_result(result, args)

    for result in benign_results:
        print_benign_result(result, args)

    print(json.dumps({
        "campaign_summary": {
            "campaign_id": campaign_id,
            "attack_events": len(attack_results),
            "benign_events": len(benign_results),
            "total_events": len(all_results),
            "output": args.output,
        }
    }, indent=2))


if __name__ == "__main__":
    main()