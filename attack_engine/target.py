import os
import time
from dataclasses import asdict
from typing import Optional, Protocol

from attack_engine.models import TargetConfig, TargetResponse
from defense_pipeline.input_firewall import InputFirewall
from defense_pipeline.output_scrubber import OutputScrubber
from defense_pipeline.target_app import LocalTargetApp


class TargetClient(Protocol):
    config: TargetConfig

    def execute(self, prompt: str) -> TargetResponse:
        ...


class MockSafeTarget:
    """
    Local mock target for unit tests.
    """

    def __init__(self):
        self.config = TargetConfig(
            name="mock_safe_target",
            model="mock-v1",
            endpoint=None,
            metadata={
                "environment": "test",
                "mode": "mock",
            },
        )

    def execute(self, prompt: str) -> TargetResponse:
        start = time.perf_counter()

        output = (
            "I can't comply with unsafe instruction overrides, tool misuse, "
            "or requests to expose sensitive information."
        )

        latency_ms = int((time.perf_counter() - start) * 1000)

        return TargetResponse(
            output_text=output,
            latency_ms=latency_ms,
            tool_calls=[],
            detected=True,
            detection_mechanism="mock_refusal_policy",
            blocked=False,
            raw_response={
                "prompt_length": len(prompt),
                "stage": "mock",
            },
        )


class LocalDefensePipelineTarget:
    """
    Local defense pipeline target adapter.

    The attack engine calls:
        target.execute(prompt)

    This adapter internally runs:
        InputFirewall -> LocalTargetApp -> OutputScrubber
    """

    def __init__(
        self,
        firewall_mode: str = "block",
        target_mode: str = "safe",
        environment: str = "local",
    ):
        self.firewall = InputFirewall(mode=firewall_mode)
        self.target_app = LocalTargetApp(mode=target_mode)
        self.output_scrubber = OutputScrubber()

        self.config = TargetConfig(
            name="local_defense_pipeline",
            model=f"local-target-app-{target_mode}",
            endpoint=None,
            metadata={
                "environment": environment,
                "firewall_mode": firewall_mode,
                "target_mode": target_mode,
            },
        )

    def execute(self, prompt: str) -> TargetResponse:
        start = time.perf_counter()

        try:
            firewall_decision = self.firewall.inspect(prompt)
            firewall_dict = asdict(firewall_decision)

            if not firewall_decision.allowed:
                latency_ms = int((time.perf_counter() - start) * 1000)

                return TargetResponse(
                    output_text="Request blocked by input firewall.",
                    latency_ms=latency_ms,
                    tool_calls=[],
                    detected=firewall_decision.detected,
                    detection_mechanism=self._format_detector_names(
                        prefix="input_firewall",
                        detector_names=firewall_decision.detector_names,
                    ),
                    blocked=True,
                    firewall_result=firewall_dict,
                    output_scrubber_result={},
                    raw_response={
                        "stage": "input_firewall",
                    },
                )

            target_result = self.target_app.generate(prompt)

            scrubber_decision = self.output_scrubber.scrub(
                target_result.output_text
            )
            scrubber_dict = asdict(scrubber_decision)

            detector_names = []

            if firewall_decision.detected:
                detector_names.extend(
                    self._prefix_detector_names(
                        "input_firewall",
                        firewall_decision.detector_names,
                    )
                )

            if scrubber_decision.detected:
                detector_names.extend(
                    self._prefix_detector_names(
                        "output_scrubber",
                        scrubber_decision.detector_names,
                    )
                )

            detected = firewall_decision.detected or scrubber_decision.detected

            latency_ms = int((time.perf_counter() - start) * 1000)

            return TargetResponse(
                output_text=scrubber_decision.output_text,
                latency_ms=latency_ms,
                tool_calls=target_result.tool_calls,
                detected=detected,
                detection_mechanism=",".join(detector_names) if detector_names else None,
                blocked=False,
                firewall_result=firewall_dict,
                output_scrubber_result=scrubber_dict,
                raw_response={
                    "stage": "completed",
                    "target_metadata": target_result.metadata,
                },
            )

        except Exception as exc:
            latency_ms = int((time.perf_counter() - start) * 1000)

            return TargetResponse(
                output_text="Target execution failed.",
                latency_ms=latency_ms,
                tool_calls=[],
                detected=False,
                detection_mechanism=None,
                blocked=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
                raw_response={
                    "stage": "error",
                },
            )

    def _prefix_detector_names(
        self,
        prefix: str,
        detector_names: list[str],
    ) -> list[str]:
        return [
            f"{prefix}:{detector_name}"
            for detector_name in detector_names
        ]

    def _format_detector_names(
        self,
        prefix: str,
        detector_names: list[str],
    ) -> Optional[str]:
        prefixed = self._prefix_detector_names(prefix, detector_names)

        if not prefixed:
            return None

        return ",".join(prefixed)


def build_target_from_name(
    target_name: str,
    firewall_mode: Optional[str] = None,
    target_mode: Optional[str] = None,
    environment: Optional[str] = None,
) -> TargetClient:
    """
    Factory for CLI target selection.
    """
    if target_name == "mock":
        return MockSafeTarget()

    if target_name == "local":
        return LocalDefensePipelineTarget(
            firewall_mode=firewall_mode or os.getenv("FIREWALL_MODE", "block"),
            target_mode=target_mode or os.getenv("TARGET_APP_MODE", "safe"),
            environment=environment or os.getenv("ENVIRONMENT", "local"),
        )

    raise ValueError(
        f"Unknown target '{target_name}'. Expected one of: mock, local"
    )