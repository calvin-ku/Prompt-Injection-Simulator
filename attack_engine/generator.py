from typing import Dict, List, Optional
from uuid import uuid4

from evaluator import SuccessEvaluator
from models import AttackDefinition, AttackExecutionResult
from mutators import PayloadMutator
from target import TargetClient
from telemetry import TelemetryBuilder


class AttackEngine:
    """
    Executes one attack definition against one target.

    The engine does not load catalogs and does not run campaigns.
    That belongs to the orchestrator.
    """

    def __init__(
        self,
        target: TargetClient,
        mutator: PayloadMutator,
        evaluator: Optional[SuccessEvaluator] = None,
        telemetry_builder: Optional[TelemetryBuilder] = None,
    ):
        self.target = target
        self.mutator = mutator
        self.evaluator = evaluator or SuccessEvaluator()
        self.telemetry_builder = telemetry_builder or TelemetryBuilder()

    def run_attack(
        self,
        campaign_id: str,
        attack: AttackDefinition,
        seed: Optional[int],
        owasp_mapping: Dict[str, str],
        atlas_mapping: Dict[str, str],
        mutations: Optional[List[str]] = None,
        random_depth: int = 3,
    ) -> AttackExecutionResult:
        if mutations is not None:
            invalid_for_attack = [
                mutation
                for mutation in mutations
                if mutation not in attack.mutations
            ]

            if invalid_for_attack:
                raise ValueError(
                    f"Mutation(s) {invalid_for_attack} are not allowed for "
                    f"attack {attack.attack_id}. Allowed: {attack.mutations}"
                )

        mutation_result = self.mutator.apply_chain(
            text=attack.payload_template,
            mutator_names=mutations,
            depth=random_depth,
        )

        response = self.target.execute(mutation_result.mutated_payload)

        evaluation = self.evaluator.evaluate(
            attack=attack,
            response=response,
        )

        owasp_id = owasp_mapping.get(attack.attack_id)
        atlas_id = atlas_mapping.get(attack.attack_id)

        telemetry = self.telemetry_builder.build_event(
            campaign_id=campaign_id,
            seed=seed,
            attack=attack,
            mutation_result=mutation_result,
            response=response,
            evaluation=evaluation,
            target_config=self.target.config,
            owasp_id=owasp_id,
            atlas_id=atlas_id,
        )

        return AttackExecutionResult(
            campaign_id=campaign_id,
            event_id=telemetry["event_id"],
            attack_id=attack.attack_id,
            original_payload=mutation_result.original_payload,
            mutated_payload=mutation_result.mutated_payload,
            mutation_chain=mutation_result.mutation_chain,
            owasp_id=owasp_id,
            atlas_id=atlas_id,
            target_response=response,
            evaluation=evaluation,
            telemetry=telemetry,
        )