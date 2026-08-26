import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from models import AttackDefinition, EvaluationResult, TargetConfig, TargetResponse
from mutators import MutationResult


class TelemetryBuilder:
    def build_event(
        self,
        campaign_id: str,
        seed: Optional[int],
        attack: AttackDefinition,
        mutation_result: MutationResult,
        response: TargetResponse,
        evaluation: EvaluationResult,
        target_config: TargetConfig,
        owasp_id: Optional[str],
        atlas_id: Optional[str],
    ) -> Dict[str, Any]:
        event_id = str(uuid.uuid4())

        mutated_payload = mutation_result.mutated_payload

        return {
            "event_id": event_id,
            "campaign_id": campaign_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "random_seed": seed,
            "attack": {
                "attack_id": attack.attack_id,
                "family": attack.family,
                "delivery": attack.delivery,
                "strategy": attack.strategy,
                "severity": attack.severity,
                "owasp_id": owasp_id,
                "atlas_id": atlas_id,
            },
            "mutation": {
                "original_payload": mutation_result.original_payload,
                "mutated_payload": mutated_payload,
                "mutation_chain": mutation_result.mutation_chain,
                "applied_mutations": [
                    {
                        "name": mutation.name,
                        "category": mutation.category.value,
                        "is_reversible": mutation.is_reversible,
                    }
                    for mutation in mutation_result.applied_mutations
                ],
            },
            "target": {
                "name": target_config.name,
                "model": target_config.model,
                "endpoint": target_config.endpoint,
                "metadata": target_config.metadata,
            },
            "result": {
                "attack_succeeded": evaluation.succeeded,
                "success_condition_type": evaluation.success_condition_type,
                "evaluation_reason": evaluation.reason,
                "defense_detected": response.detected,
                "detection_mechanism": response.detection_mechanism,
            },
            "features": {
                "payload_length": len(mutated_payload),
                "payload_entropy": self._shannon_entropy(mutated_payload),
            },
            "request_response": {
                "latency_ms": response.latency_ms,
                "tool_calls": response.tool_calls,
                "response_preview": response.output_text[:500],
                "raw_response": response.raw_response,
            },
        }

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0

        frequencies = {}

        for character in text:
            frequencies[character] = frequencies.get(character, 0) + 1

        entropy = 0.0
        length = len(text)

        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 5)