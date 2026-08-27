import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from attack_engine.models import (
    AttackDefinition,
    EvaluationResult,
    TargetConfig,
    TargetResponse,
)
from attack_engine.mutators import MutationResult
from defense_pipeline.features import shannon_entropy


class TelemetryBuilder:
    SCHEMA_VERSION = "1.0.0"

    SENSITIVE_FIELD_MARKERS = [
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "credential",
        "authorization",
    ]

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
        """
        Build telemetry for an adversarial attack execution.
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        environment = target_config.metadata.get("environment", "unknown")

        firewall_result = response.firewall_result or {}
        scrubber_result = response.output_scrubber_result or {}

        firewall_features = firewall_result.get("features", {})
        scrubber_features = scrubber_result.get("features", {})

        detector_names = self._extract_detector_names(response)

        return {
            "event_id": event_id,
            "campaign_id": campaign_id,
            "timestamp": timestamp,
            "schema_version": self.SCHEMA_VERSION,

            "event": {
                "kind": "alert" if response.detected else "event",
                "category": "llm_security",
                "type": "adversarial_test",
                "outcome": "success" if evaluation.succeeded else "failure",
                "status": "error" if response.error_type else "completed",
            },

            "attack": {
                "id": attack.attack_id,
                "attack_id": attack.attack_id,
                "family": attack.family,
                "delivery": attack.delivery,
                "strategy": attack.strategy,
                "severity": attack.severity,
                "succeeded": evaluation.succeeded,
                "success_condition_type": evaluation.success_condition_type,
                "evaluation_reason": evaluation.reason,
            },

            "owasp": {
                "id": owasp_id,
            },

            "mitre_atlas": {
                "id": atlas_id,
            },

            "mutation": {
                "chain": mutation_result.mutation_chain,
                "count": len(mutation_result.mutation_chain),
                "categories": [
                    mutation.category.value
                    for mutation in mutation_result.applied_mutations
                ],
                "applied": [
                    {
                        "name": mutation.name,
                        "category": mutation.category.value,
                        "is_reversible": mutation.is_reversible,
                    }
                    for mutation in mutation_result.applied_mutations
                ],
                "original_payload": mutation_result.original_payload,
                "mutated_payload": mutation_result.mutated_payload,
            },

            "target": {
                "name": target_config.name,
                "model": target_config.model,
                "environment": environment,
                "container": socket.gethostname(),
                "endpoint": target_config.endpoint,
                "metadata": self._sanitize_value(target_config.metadata),
            },

            "defense": {
                "detected": response.detected,
                "blocked": response.blocked,
                "detection_mechanism": response.detection_mechanism,
                "detector_names": detector_names,
                "firewall_result": self._sanitize_value(firewall_result),
                "output_scrubber_result": self._sanitize_value(
                    scrubber_result
                ),
                "risk_score": firewall_result.get("risk_score"),
                "firewall_action": firewall_result.get("action"),
                "firewall_entropy": firewall_features.get("entropy"),
                "output_entropy": scrubber_features.get("entropy"),
            },

            "features": {
                "payload_length": len(mutation_result.mutated_payload),
                "payload_entropy": shannon_entropy(
                    mutation_result.mutated_payload
                ),
                "firewall_features": firewall_features,
                "output_features": scrubber_features,
            },

            "result": {
                "attack_succeeded": evaluation.succeeded,
                "defense_detected": response.detected,
                "blocked": response.blocked,
                "error": response.error_type is not None,
            },

            "performance": {
                "latency_ms": response.latency_ms,
            },

            "request_response": {
                "tool_calls": response.tool_calls,
                "response_preview": response.output_text[:500],
                "raw_response": self._sanitize_value(response.raw_response),
            },

            "error": {
                "type": response.error_type,
                "message": response.error_message,
            },

            "reproducibility": {
                "random_seed": seed,
            },
        }

    def build_benign_event(
        self,
        campaign_id: str,
        sample_id: str,
        category: str,
        prompt: str,
        expected_result: str,
        response: TargetResponse,
        target_config: TargetConfig,
    ) -> Dict[str, Any]:
        """
        Build telemetry for a legitimate benign request.

        A defense detection on benign traffic is counted as a
        false-positive detection.

        A block on benign traffic is recorded separately so the benchmark
        can distinguish false-positive detection from actual user impact.
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        environment = target_config.metadata.get("environment", "unknown")

        firewall_result = response.firewall_result or {}
        scrubber_result = response.output_scrubber_result or {}

        firewall_features = firewall_result.get("features", {})
        scrubber_features = scrubber_result.get("features", {})

        detector_names = self._extract_detector_names(response)

        false_positive = bool(response.detected)
        benign_blocked = bool(response.blocked)

        benchmark_succeeded = (
            not false_positive
            and not benign_blocked
            and response.error_type is None
        )

        return {
            "event_id": event_id,
            "campaign_id": campaign_id,
            "timestamp": timestamp,
            "schema_version": self.SCHEMA_VERSION,

            "event": {
                "kind": "alert" if response.detected else "event",
                "category": "llm_security",
                "type": "benign_test",
                "outcome": (
                    "success"
                    if benchmark_succeeded
                    else "failure"
                ),
                "status": "error" if response.error_type else "completed",
            },

            "sample": {
                "id": sample_id,
                "sample_id": sample_id,
                "category": category,
                "expected_result": expected_result,
            },

            "target": {
                "name": target_config.name,
                "model": target_config.model,
                "environment": environment,
                "container": socket.gethostname(),
                "endpoint": target_config.endpoint,
                "metadata": self._sanitize_value(target_config.metadata),
            },

            "defense": {
                "detected": response.detected,
                "blocked": response.blocked,
                "detection_mechanism": response.detection_mechanism,
                "detector_names": detector_names,
                "firewall_result": self._sanitize_value(firewall_result),
                "output_scrubber_result": self._sanitize_value(
                    scrubber_result
                ),
                "risk_score": firewall_result.get("risk_score"),
                "firewall_action": firewall_result.get("action"),
                "firewall_entropy": firewall_features.get("entropy"),
                "output_entropy": scrubber_features.get("entropy"),
            },

            "features": {
                "prompt_length": len(prompt),
                "prompt_entropy": shannon_entropy(prompt),
                "firewall_features": firewall_features,
                "output_features": scrubber_features,
            },

            "result": {
                "false_positive": false_positive,
                "benign_blocked": benign_blocked,
                "defense_detected": response.detected,
                "blocked": response.blocked,
                "error": response.error_type is not None,
            },

            "performance": {
                "latency_ms": response.latency_ms,
            },

            "request_response": {
                "prompt": prompt,
                "tool_calls": response.tool_calls,
                "response_preview": response.output_text[:500],
                "raw_response": self._sanitize_value(response.raw_response),
            },

            "error": {
                "type": response.error_type,
                "message": response.error_message,
            },

            "reproducibility": {
                "random_seed": None,
            },
        }

    def _extract_detector_names(
        self,
        response: TargetResponse,
    ) -> list[str]:
        if not response.detection_mechanism:
            return []

        return [
            item.strip()
            for item in response.detection_mechanism.split(",")
            if item.strip()
        ]

    def _sanitize_value(self, value: Any) -> Any:
        """
        Recursively remove obvious secret-like fields from telemetry.
        """
        if isinstance(value, dict):
            sanitized = {}

            for key, item in value.items():
                normalized_key = str(key).lower()

                if any(
                    marker in normalized_key
                    for marker in self.SENSITIVE_FIELD_MARKERS
                ):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_value(item)

            return sanitized

        if isinstance(value, list):
            return [
                self._sanitize_value(item)
                for item in value
            ]

        return value