from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from attack_engine.benign import (
    BenignExecutionResult,
    BenignRunner,
)
from attack_engine.generator import AttackEngine
from attack_engine.models import AttackExecutionResult
from telemetry.ecs_logger import ECSJsonlLogger
from telemetry.telemetry import TelemetryBuilder


ExecutionResult = Union[
    AttackExecutionResult,
    BenignExecutionResult,
]


class CampaignOrchestrator:
    """
    Runs attack and benign benchmark campaigns.

    The orchestrator owns campaign IDs, batch runs,
    result collection, telemetry construction for benign
    executions, and delegates JSONL persistence to the
    telemetry logging layer.
    """

    def __init__(
        self,
        engine: AttackEngine,
        telemetry_builder: Optional[TelemetryBuilder] = None,
    ):
        self.engine = engine
        self.telemetry_builder = (
            telemetry_builder or TelemetryBuilder()
        )

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
        """
        Run one canonical attack once.
        """
        campaign_id = campaign_id or str(uuid4())

        if attack_id not in attacks:
            raise ValueError(
                f"Unknown attack_id: {attack_id}"
            )

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
        variants_per_attack: int = 1,
        campaign_id: Optional[str] = None,
    ) -> List[AttackExecutionResult]:
        """
        Run a full adversarial campaign.

        Each canonical attack can be executed multiple times
        using variants_per_attack.

        Example:
            8 attacks x 100 variants = 800 executions.
        """
        campaign_id = campaign_id or str(uuid4())

        if variants_per_attack < 1:
            raise ValueError(
                "variants_per_attack must be at least 1"
            )

        selected_attack_ids = (
            attack_ids or list(attacks.keys())
        )

        results = []

        for attack_id in selected_attack_ids:
            for variant_index in range(
                1,
                variants_per_attack + 1,
            ):
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

                result.telemetry.setdefault(
                    "attack",
                    {},
                )["variant_index"] = variant_index

                result.telemetry.setdefault(
                    "reproducibility",
                    {},
                )["variant_index"] = variant_index

                results.append(result)

        return results

    def run_benign_campaign(
        self,
        runner: BenignRunner,
        samples: List[Dict[str, Any]],
        campaign_id: Optional[str] = None,
    ) -> List[BenignExecutionResult]:
        """
        Run legitimate traffic through the same target
        and defense pipeline.

        Benign prompts are not mutated.
        """
        campaign_id = campaign_id or str(uuid4())

        results = []

        for sample in samples:
            result = runner.run_sample(
                sample
            )

            result.telemetry = (
                self.telemetry_builder.build_benign_event(
                    campaign_id=campaign_id,
                    sample_id=result.sample_id,
                    category=result.category,
                    prompt=result.prompt,
                    expected_result=(
                        result.expected_result
                    ),
                    response=(
                        result.target_response
                    ),
                    target_config=(
                        runner.target.config
                    ),
                )
            )

            results.append(result)

        return results

    def write_telemetry_jsonl(
        self,
        results: List[ExecutionResult],
        output_path: str,
    ) -> None:
        """
        Write all campaign telemetry to one JSONL file.
        """
        logger = ECSJsonlLogger(
            output_path
        )

        logger.write_events(
            (
                result.telemetry
                for result in results
            ),
            append=False,
        )