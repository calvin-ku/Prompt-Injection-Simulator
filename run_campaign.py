import argparse
import json

from attack_engine.generator import AttackEngine
from attack_engine.mutators import PayloadMutator
from attack_engine.orchestrator import CampaignOrchestrator
from attack_engine.validator import CatalogValidator
from attack_engine.target import MockSafeTarget


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
        "--output",
        default="runs/latest_campaign.jsonl",
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

    target = MockSafeTarget()

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
            "latency_ms": result.target_response.latency_ms,
            "random_seed": args.seed,
        }, indent=2))


if __name__ == "__main__":
    main()