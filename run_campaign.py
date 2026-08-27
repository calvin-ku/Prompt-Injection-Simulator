import argparse
import json

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


def main():
    parser = argparse.ArgumentParser(
        description="Run a reproducible LLM attack benchmark campaign."
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
        "--attack",
        help="Specific attack_id to run. If omitted, runs all attacks.",
    )

    parser.add_argument(
        "--mutations",
        default=None,
        help="Comma-separated mutation chain, e.g. base64,homoglyph,xml",
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
        help="Target backend to run attacks against.",
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

    args = parser.parse_args()

    mutator = PayloadMutator(seed=args.seed)

    validator = CatalogValidator(
        mutator_names=set(mutator.registry.keys())
    )

    attacks, owasp_mapping, atlas_mapping = validator.validate_all(
        attack_catalog_path=args.attack_catalog,
        owasp_mapping_path=args.owasp_mapping,
        atlas_mapping_path=args.atlas_mapping,
    )

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
        )

        results = [result]

    else:
        results = orchestrator.run_campaign(
            attacks=attacks,
            owasp_mapping=owasp_mapping,
            atlas_mapping=atlas_mapping,
            seed=args.seed,
            mutations=mutations,
            random_depth=args.random_depth,
        )

    orchestrator.write_telemetry_jsonl(
        results=results,
        output_path=args.output,
    )

    for result in results:
        print(json.dumps({
            "campaign_id": result.campaign_id,
            "event_id": result.event_id,
            "attack_id": result.attack_id,
            "owasp_id": result.owasp_id,
            "atlas_id": result.atlas_id,
            "mutation_chain": result.mutation_chain,
            "attack_succeeded": result.evaluation.succeeded,
            "defense_detected": result.target_response.detected,
            "blocked": result.target_response.blocked,
            "detection_mechanism": result.target_response.detection_mechanism,
            "latency_ms": result.target_response.latency_ms,
            "random_seed": args.seed,
            "target": args.target,
        }, indent=2))


if __name__ == "__main__":
    main()