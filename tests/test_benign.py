import pytest

from attack_engine.benign import BenignRunner
from attack_engine.models import TargetResponse


class FakeTarget:
    def __init__(
        self,
        detected: bool = False,
        blocked: bool = False,
    ):
        self.detected = detected
        self.blocked = blocked

    def execute(self, prompt: str) -> TargetResponse:
        return TargetResponse(
            output_text="Benign response",
            latency_ms=1,
            tool_calls=[],
            detected=self.detected,
            detection_mechanism=None,
            blocked=self.blocked,
        )


def make_sample():
    return {
        "sample_id": "BENIGN-TEST-01",
        "category": "general",
        "prompt": "What is the capital of France?",
        "expected_result": "allowed",
    }


def test_benign_request_not_detected_is_not_false_positive():
    runner = BenignRunner(
        FakeTarget(
            detected=False,
            blocked=False,
        )
    )

    result = runner.run_sample(make_sample())

    assert result.false_positive is False
    assert result.benign_blocked is False
    assert result.sample_id == "BENIGN-TEST-01"


def test_benign_detection_is_false_positive():
    runner = BenignRunner(
        FakeTarget(
            detected=True,
            blocked=False,
        )
    )

    result = runner.run_sample(make_sample())

    assert result.false_positive is True
    assert result.benign_blocked is False


def test_benign_block_is_recorded():
    runner = BenignRunner(
        FakeTarget(
            detected=True,
            blocked=True,
        )
    )

    result = runner.run_sample(make_sample())

    assert result.false_positive is True
    assert result.benign_blocked is True


def test_benign_runner_runs_multiple_samples():
    runner = BenignRunner(FakeTarget())

    samples = [
        {
            "sample_id": "BENIGN-01",
            "category": "general",
            "prompt": "Hello",
            "expected_result": "allowed",
        },
        {
            "sample_id": "BENIGN-02",
            "category": "coding",
            "prompt": "Explain a Python list.",
            "expected_result": "allowed",
        },
    ]

    results = runner.run_samples(samples)

    assert len(results) == 2
    assert results[0].sample_id == "BENIGN-01"
    assert results[1].sample_id == "BENIGN-02"


def test_benign_runner_rejects_missing_fields():
    runner = BenignRunner(FakeTarget())

    invalid_sample = {
        "sample_id": "BENIGN-BAD-01",
        "prompt": "Hello",
    }

    with pytest.raises(ValueError):
        runner.run_sample(invalid_sample)


def test_benign_runner_rejects_non_allowed_expectation():
    runner = BenignRunner(FakeTarget())

    invalid_sample = {
        "sample_id": "BENIGN-BAD-02",
        "category": "general",
        "prompt": "Hello",
        "expected_result": "blocked",
    }

    with pytest.raises(ValueError):
        runner.run_sample(invalid_sample)