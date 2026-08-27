from dataclasses import dataclass
from typing import Any, Dict, List

from attack_engine.models import TargetResponse


@dataclass
class BenignExecutionResult:
    """
    Result of running one legitimate/benign prompt through the target.

    A benign request should normally be allowed without detection.
    """

    sample_id: str
    category: str
    prompt: str
    expected_result: str
    target_response: TargetResponse
    false_positive: bool
    benign_blocked: bool


class BenignRunner:
    """
    Executes benign samples against the same target used by attacks.

    Benign prompts are intentionally NOT mutated. Their purpose is to
    measure whether the defense incorrectly detects or blocks legitimate
    user traffic.
    """

    REQUIRED_FIELDS = {
        "sample_id",
        "category",
        "prompt",
        "expected_result",
    }

    def __init__(self, target: Any):
        self.target = target

    def validate_sample(self, sample: Dict[str, Any]) -> None:
        missing_fields = self.REQUIRED_FIELDS - sample.keys()

        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(
                f"Benign sample is missing required fields: {missing}"
            )

        if sample["expected_result"] != "allowed":
            raise ValueError(
                "Benign samples must have expected_result='allowed'"
            )

        if not sample["sample_id"]:
            raise ValueError("Benign sample_id cannot be empty")

        if not sample["prompt"]:
            raise ValueError("Benign prompt cannot be empty")

    def run_sample(
        self,
        sample: Dict[str, Any],
    ) -> BenignExecutionResult:
        self.validate_sample(sample)

        response = self.target.execute(sample["prompt"])

        defense_detected = bool(response.detected)
        blocked = bool(response.blocked)

        return BenignExecutionResult(
            sample_id=sample["sample_id"],
            category=sample["category"],
            prompt=sample["prompt"],
            expected_result=sample["expected_result"],
            target_response=response,
            false_positive=defense_detected,
            benign_blocked=blocked,
        )

    def run_samples(
        self,
        samples: List[Dict[str, Any]],
    ) -> List[BenignExecutionResult]:
        return [
            self.run_sample(sample)
            for sample in samples
        ]