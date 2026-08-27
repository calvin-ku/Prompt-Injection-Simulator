from typing import Any, Dict, List, Optional

from attack_engine.evaluator import SuccessEvaluator
from attack_engine.models import (
    AttackDefinition,
    AttackExecutionResult,
)
from attack_engine.mutators import PayloadMutator
from attack_engine.target import TargetClient
from telemetry.telemetry import TelemetryBuilder


class AttackEngine:
    """
    Generates and executes one attack instance against one target.

    The engine does not load catalogs and does not run campaigns.
    Campaign coordination, variant counting, and duplicate prevention
    belong to the orchestrator.
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

        self.evaluator = (
            evaluator
            or SuccessEvaluator()
        )

        self.telemetry_builder = (
            telemetry_builder
            or TelemetryBuilder()
        )

    def generate_mutation(
        self,
        attack: AttackDefinition,
        seed: Optional[int],
        mutations: Optional[List[str]] = None,
        random_depth: int = 3,
    ) -> Any:
        """
        Generate one mutated attack payload without executing it.

        A fresh mutator is created from the supplied seed so that
        a variant can be reproduced independently of every other
        execution in the campaign.
        """

        # -----------------------------------------------------
        # Validate explicitly requested mutations
        # -----------------------------------------------------

        if mutations is not None:
            invalid_for_attack = [
                mutation
                for mutation in mutations
                if mutation not in attack.mutations
            ]

            if invalid_for_attack:
                raise ValueError(
                    f"Mutation(s) {invalid_for_attack} "
                    f"are not allowed for attack "
                    f"{attack.attack_id}. "
                    f"Allowed: {attack.mutations}"
                )

        # -----------------------------------------------------
        # Fresh seeded mutator for this individual variant
        # -----------------------------------------------------

        execution_mutator = PayloadMutator(
            seed=seed
        )

        # -----------------------------------------------------
        # Select mutation chain
        # -----------------------------------------------------

        if mutations is not None:
            selected_mutations = mutations

        else:
            selected_mutations = (
                execution_mutator.build_random_chain(
                    allowed_mutators=attack.mutations,
                    depth=random_depth,
                )
            )

        # -----------------------------------------------------
        # Apply mutation chain
        # -----------------------------------------------------

        mutation_result = (
            execution_mutator.apply_chain(
                text=attack.payload_template,
                mutator_names=selected_mutations,
                depth=random_depth,
            )
        )

        return mutation_result

    def execute_mutation(
        self,
        campaign_id: str,
        attack: AttackDefinition,
        mutation_result: Any,
        seed: Optional[int],
        owasp_mapping: Dict[str, str],
        atlas_mapping: Dict[str, str],
    ) -> AttackExecutionResult:
        """
        Execute a mutation that has already been generated.

        Separating generation from execution lets the orchestrator
        reject duplicate payloads before they are sent to a target.
        """

        # -----------------------------------------------------
        # Execute against target
        # -----------------------------------------------------

        response = self.target.execute(
            mutation_result.mutated_payload
        )

        # -----------------------------------------------------
        # Evaluate result
        # -----------------------------------------------------

        evaluation = self.evaluator.evaluate(
            attack=attack,
            response=response,
        )

        # -----------------------------------------------------
        # Framework mappings
        # -----------------------------------------------------

        owasp_id = owasp_mapping.get(
            attack.attack_id
        )

        atlas_id = atlas_mapping.get(
            attack.attack_id
        )

        # -----------------------------------------------------
        # Telemetry
        # -----------------------------------------------------

        telemetry = (
            self.telemetry_builder.build_event(
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
        )

        # -----------------------------------------------------
        # Final execution result
        # -----------------------------------------------------

        return AttackExecutionResult(
            campaign_id=campaign_id,
            event_id=telemetry["event_id"],
            attack_id=attack.attack_id,
            original_payload=(
                mutation_result.original_payload
            ),
            mutated_payload=(
                mutation_result.mutated_payload
            ),
            mutation_chain=(
                mutation_result.mutation_chain
            ),
            owasp_id=owasp_id,
            atlas_id=atlas_id,
            target_response=response,
            evaluation=evaluation,
            telemetry=telemetry,
        )

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
        """
        Generate and execute one attack instance.

        This remains the convenient single-execution API used by
        callers that do not need campaign-level duplicate handling.
        """

        mutation_result = self.generate_mutation(
            attack=attack,
            seed=seed,
            mutations=mutations,
            random_depth=random_depth,
        )

        return self.execute_mutation(
            campaign_id=campaign_id,
            attack=attack,
            mutation_result=mutation_result,
            seed=seed,
            owasp_mapping=owasp_mapping,
            atlas_mapping=atlas_mapping,
        )