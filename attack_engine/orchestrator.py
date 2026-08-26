import json
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from engine import AttackEngine
from models import AttackExecutionResult


class CampaignOrchestrator:
    """
    Runs one attack or an entire campaign.

    The orchestrator owns campaign IDs, output files, batch runs,
    and result collection.
    """

    def __init__(self, engine: AttackEngine):
        self.engine = engine

    def run_single_attack(
        self,
        attack_id: str,
        attacks: dict,
        owasp_mapping: dict,
        atlas_mapping: dict,
        seed: Optional[int],
        mutations: Optional[List[str]] = None,
        random_depth: int = 3,
        campaign_id: Optional[str] = None,
    ) -> AttackExecutionResult:
        campaign_id = campaign_id or str(uuid4())

        if attack_id not in attacks:
            raise ValueError(f"Unknown attack_id: {attack_id}")

        attack = attacks[attack_id]

        return self.engine.run_attack(
            campaign_id=campaign_id,
            attack=attack,
            seed=seed,
            owasp_mapping=owasp_mapping,
            atlas_mapping=atlas_mapping,
            mutations=mutations,
            random_depth=random_depth,
        )

    def run_campaign(
        self,
        attacks: dict,
        owasp_mapping: dict,
        atlas_mapping: dict,
        seed: Optional[int],
        attack_ids: Optional[List[str]] = None,
        mutations: Optional[List[str]] = None,
        random_depth: int = 3,
        campaign_id: Optional[str] = None,
    ) -> List[AttackExecutionResult]:
        campaign_id = campaign_id or str(uuid4())

        selected_attack_ids = attack_ids or list(attacks.keys())

        results = []

        for attack_id in selected_attack_ids:
            result = self.run_single_attack(
                attack_id=attack_id,
                attacks=attacks,
                owasp_mapping=owasp_mapping,
                atlas_mapping=atlas_mapping,
                seed=seed,
                mutations=mutations,
                random_depth=random_depth,
                campaign_id=campaign_id,
            )

            results.append(result)

        return results

    def write_telemetry_jsonl(
        self,
        results: List[AttackExecutionResult],
        output_path: str,
    ) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as file:
            for result in results:
                file.write(json.dumps(result.telemetry) + "\n")