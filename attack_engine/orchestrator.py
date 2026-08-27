import hashlib
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
    Coordinates adversarial and benign benchmark campaigns.

    Responsibilities:
    - campaign IDs
    - variant generation
    - duplicate prevention
    - variant reproducibility
    - benign execution
    - telemetry persistence

    Individual attack execution remains inside AttackEngine.
    """

    def __init__(
        self,
        engine: AttackEngine,
        telemetry_builder: Optional[TelemetryBuilder] = None,
    ):
        self.engine = engine

        self.telemetry_builder = (
            telemetry_builder
            or TelemetryBuilder()
        )

    @staticmethod
    def _build_variant_seed(
        base_seed: Optional[int],
        attack_id: str,
        variant_index: int,
        attempt_index: int,
    ) -> Optional[int]:
        """
        Build a stable seed for one generated candidate.

        The same:
            base seed
            attack ID
            variant index
            generation attempt

        will always produce the same variant seed.

        SHA-256 avoids depending on Python's process-randomized hash().
        """

        if base_seed is None:
            return None

        seed_material = (
            f"{base_seed}:"
            f"{attack_id}:"
            f"{variant_index}:"
            f"{attempt_index}"
        )

        digest = hashlib.sha256(
            seed_material.encode("utf-8")
        ).digest()

        # Use a stable 32-bit integer seed.
        return int.from_bytes(
            digest[:4],
            byteorder="big",
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
        Execute one attack once.
        """

        campaign_id = (
            campaign_id
            or str(uuid4())
        )

        if attack_id not in attacks:
            raise ValueError(
                f"Unknown attack_id: {attack_id}"
            )

        attack = attacks[
            attack_id
        ]

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
        max_attempts_per_variant: int = 25,
    ) -> List[AttackExecutionResult]:
        """
        Run an adversarial benchmark campaign.

        Each canonical attack can generate multiple unique variants.

        Duplicate mutated payloads are rejected before reaching the
        target.

        Example:
            8 attacks x 100 variants = 800 unique executions,
            assuming each attack's mutation space can produce at
            least 100 unique payloads.
        """

        campaign_id = (
            campaign_id
            or str(uuid4())
        )

        if variants_per_attack < 1:
            raise ValueError(
                "variants_per_attack must be at least 1"
            )

        if max_attempts_per_variant < 1:
            raise ValueError(
                "max_attempts_per_variant "
                "must be at least 1"
            )

        selected_attack_ids = (
            attack_ids
            or list(attacks.keys())
        )

        results = []

        # -----------------------------------------------------
        # Run each canonical attack
        # -----------------------------------------------------

        for attack_id in selected_attack_ids:
            if attack_id not in attacks:
                raise ValueError(
                    f"Unknown attack_id: {attack_id}"
                )

            attack = attacks[
                attack_id
            ]

            # Uniqueness is tracked separately for each
            # canonical attack.
            seen_payloads = set()

            # -------------------------------------------------
            # Generate requested number of variants
            # -------------------------------------------------

            for variant_index in range(
                1,
                variants_per_attack + 1,
            ):
                accepted_result = None

                # ---------------------------------------------
                # Retry generation when duplicate payloads
                # appear.
                # ---------------------------------------------

                for attempt_index in range(
                    max_attempts_per_variant
                ):
                    variant_seed = (
                        self._build_variant_seed(
                            base_seed=seed,
                            attack_id=attack_id,
                            variant_index=(
                                variant_index
                            ),
                            attempt_index=(
                                attempt_index
                            ),
                        )
                    )

                    # -----------------------------------------
                    # Generate candidate WITHOUT executing it.
                    # -----------------------------------------

                    mutation_result = (
                        self.engine.generate_mutation(
                            attack=attack,
                            seed=variant_seed,
                            mutations=mutations,
                            random_depth=random_depth,
                        )
                    )

                    payload = (
                        mutation_result.mutated_payload
                    )

                    # -----------------------------------------
                    # Duplicate?
                    #
                    # Do not send it to the target.
                    # Generate another candidate instead.
                    # -----------------------------------------

                    if payload in seen_payloads:
                        continue

                    # -----------------------------------------
                    # Unique candidate accepted.
                    # -----------------------------------------

                    seen_payloads.add(
                        payload
                    )

                    accepted_result = (
                        self.engine.execute_mutation(
                            campaign_id=campaign_id,
                            attack=attack,
                            mutation_result=(
                                mutation_result
                            ),
                            seed=variant_seed,
                            owasp_mapping=(
                                owasp_mapping
                            ),
                            atlas_mapping=(
                                atlas_mapping
                            ),
                        )
                    )

                    # -----------------------------------------
                    # Variant telemetry
                    # -----------------------------------------

                    accepted_result.telemetry.setdefault(
                        "attack",
                        {},
                    )["variant_index"] = (
                        variant_index
                    )

                    reproducibility = (
                        accepted_result.telemetry.setdefault(
                            "reproducibility",
                            {},
                        )
                    )

                    reproducibility[
                        "base_seed"
                    ] = seed

                    reproducibility[
                        "variant_seed"
                    ] = variant_seed

                    reproducibility[
                        "variant_index"
                    ] = variant_index

                    reproducibility[
                        "generation_attempt"
                    ] = (
                        attempt_index + 1
                    )

                    break

                # ---------------------------------------------
                # Retry limit exhausted.
                # ---------------------------------------------

                if accepted_result is None:
                    raise RuntimeError(
                        "Unable to generate a unique "
                        f"variant for attack "
                        f"{attack_id} at "
                        f"variant_index={variant_index} "
                        f"after "
                        f"{max_attempts_per_variant} "
                        "attempts. "
                        "The mutation space for this "
                        "attack may be too small or "
                        "too deterministic."
                    )

                results.append(
                    accepted_result
                )

        return results

    def run_benign_campaign(
        self,
        runner: BenignRunner,
        samples: List[Dict[str, Any]],
        campaign_id: Optional[str] = None,
    ) -> List[BenignExecutionResult]:
        """
        Execute legitimate traffic through the same
        target and defense pipeline.

        Benign samples are intentionally not mutated.
        """

        campaign_id = (
            campaign_id
            or str(uuid4())
        )

        results = []

        for sample in samples:
            result = runner.run_sample(
                sample
            )

            result.telemetry = (
                self.telemetry_builder.build_benign_event(
                    campaign_id=campaign_id,
                    sample_id=(
                        result.sample_id
                    ),
                    category=(
                        result.category
                    ),
                    prompt=(
                        result.prompt
                    ),
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

            results.append(
                result
            )

        return results

    def write_telemetry_jsonl(
        self,
        results: List[ExecutionResult],
        output_path: str,
    ) -> None:
        """
        Write complete campaign telemetry to JSONL.
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