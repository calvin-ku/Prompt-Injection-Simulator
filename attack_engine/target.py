import time
from typing import Protocol

from models import TargetConfig, TargetResponse


class TargetClient(Protocol):
    config: TargetConfig

    def execute(self, prompt: str) -> TargetResponse:
        ...


class MockSafeTarget:
    """
    Local mock target for testing the pipeline safely.

    Replace this with an OpenAI, Anthropic, local model, or internal
    test harness client later.
    """

    def __init__(self):
        self.config = TargetConfig(
            name="mock_safe_target",
            model="mock-v1",
            endpoint=None,
            metadata={"mode": "local-test"},
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
            raw_response={
                "prompt_length": len(prompt),
            },
        )