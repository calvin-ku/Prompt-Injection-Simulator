import math
import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class FirewallDecision:
    allowed: bool
    detected: bool
    detector_names: List[str] = field(default_factory=list)
    reason: str = ""
    features: Dict[str, float] = field(default_factory=dict)


class InputFirewall:
    """
    Lightweight local input firewall.

    This is intentionally simple for the first real pipeline version.
    It detects suspicious prompt-injection style inputs and can either
    block or allow them depending on mode.

    mode="block"   -> detected attacks are blocked before target app
    mode="monitor" -> detected attacks are logged but still sent onward
    """

    SUSPICIOUS_PATTERNS = {
        "instruction_override": re.compile(
            r"(?i)(ignore previous|ignore all previous|system override|developer message|bypass safety)"
        ),
        "secret_exfiltration": re.compile(
            r"(?i)(api[_ -]?key|password|secret|token|credential|policy number)"
        ),
        "tool_abuse": re.compile(
            r"(?i)(send_email|database_drop|remove the users table|without asking for confirmation)"
        ),
        "xss_payload": re.compile(
            r"(?i)(<script|document\.cookie|fetch\()"
        ),
        "resource_exhaustion": re.compile(
            r"(?i)(repeat this loop|500 times|infinite loop|never stop)"
        ),
    }

    def __init__(self, mode: str = "block", entropy_threshold: float = 4.8):
        if mode not in {"block", "monitor"}:
            raise ValueError("Firewall mode must be either 'block' or 'monitor'")

        self.mode = mode
        self.entropy_threshold = entropy_threshold

    def inspect(self, prompt: str) -> FirewallDecision:
        if not isinstance(prompt, str):
            return FirewallDecision(
                allowed=False,
                detected=True,
                detector_names=["invalid_input_type"],
                reason="Prompt must be a string.",
                features={},
            )

        detectors = []
        entropy = self._shannon_entropy(prompt)

        for detector_name, pattern in self.SUSPICIOUS_PATTERNS.items():
            if pattern.search(prompt):
                detectors.append(detector_name)

        if entropy >= self.entropy_threshold and len(prompt) > 40:
            detectors.append("high_entropy_payload")

        detected = len(detectors) > 0
        allowed = not detected or self.mode == "monitor"

        return FirewallDecision(
            allowed=allowed,
            detected=detected,
            detector_names=detectors,
            reason=(
                "Input allowed."
                if allowed
                else "Input blocked by firewall."
            ),
            features={
                "entropy": entropy,
                "prompt_length": float(len(prompt)),
            },
        )

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