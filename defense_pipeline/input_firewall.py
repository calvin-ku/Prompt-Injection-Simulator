import re
from dataclasses import dataclass, field
from typing import Dict, List

from defense_pipeline.features import extract_text_features


@dataclass
class FirewallDecision:
    allowed: bool
    detected: bool
    action: str
    risk_score: int
    detector_names: List[str] = field(default_factory=list)
    reason: str = ""
    features: Dict = field(default_factory=dict)


class InputFirewall:
    """
    Local scoring input firewall.

    mode="block":
        High-risk prompts are blocked before reaching the target app.

    mode="monitor":
        High-risk prompts are detected and logged but still sent to the target app.

    This is a baseline feature/rule firewall. It is not meant to be the final
    production-grade detector, but it gives the framework real measurable
    defense decisions.
    """

    DETECTION_RULES = {
        "instruction_override": {
            "pattern": re.compile(
                r"(?i)(ignore previous|ignore all previous|system override|"
                r"developer message|bypass safety|ignore instructions|"
                r"print ['\"]?SYSTEM_COMPROMISED|SYSTEM_COMPROMISED)"
            ),
            "score": 40,
        },
        "secret_exfiltration": {
            "pattern": re.compile(
                r"(?i)(api[_ -]?key|password|secret|token|credential|"
                r"policy number|mailing address|discount code)"
            ),
            "score": 35,
        },
        "tool_abuse": {
            "pattern": re.compile(
                r"(?i)(send_email|database_drop|remove the users table|"
                r"without asking for confirmation|unauthorized action)"
            ),
            "score": 40,
        },
        "xss_payload": {
            "pattern": re.compile(
                r"(?i)(<script|document\.cookie|fetch\(|javascript:)"
            ),
            "score": 35,
        },
        "resource_exhaustion": {
            "pattern": re.compile(
                r"(?i)(repeat this loop|500 times|infinite loop|never stop|"
                r"repeat forever)"
            ),
            "score": 30,
        },
        "jailbreak_roleplay": {
            "pattern": re.compile(
                r"(?i)(you are now dan|broken free|stay fully in character|"
                r"refusal costs|token game)"
            ),
            "score": 30,
        },
    }

    def __init__(
        self,
        mode: str = "block",
        block_threshold: int = 50,
        detect_threshold: int = 25,
        entropy_threshold: float = 4.8,
    ):
        if mode not in {"block", "monitor"}:
            raise ValueError("Firewall mode must be either 'block' or 'monitor'")

        self.mode = mode
        self.block_threshold = block_threshold
        self.detect_threshold = detect_threshold
        self.entropy_threshold = entropy_threshold

    def inspect(self, prompt: str) -> FirewallDecision:
        if not isinstance(prompt, str):
            return FirewallDecision(
                allowed=False,
                detected=True,
                action="block",
                risk_score=100,
                detector_names=["invalid_input_type"],
                reason="Prompt must be a string.",
                features={},
            )

        features = extract_text_features(prompt)
        detector_names = []
        risk_score = 0

        for detector_name, rule in self.DETECTION_RULES.items():
            if rule["pattern"].search(prompt):
                detector_names.append(detector_name)
                risk_score += rule["score"]

        if features.entropy >= self.entropy_threshold and features.length > 40:
            detector_names.append("high_entropy_payload")
            risk_score += 20

        if features.zero_width_count > 0:
            detector_names.append("zero_width_unicode")
            risk_score += 20

        if features.suspicious_mixed_script:
            detector_names.append("suspicious_mixed_script")
            risk_score += 15

        if features.base64_like:
            detector_names.append("embedded_base64_payload")
            risk_score += 20

        if features.hex_like:
            detector_names.append("embedded_hex_payload")
            risk_score += 20

        if features.structural_marker_count > 0:
            detector_names.append("structured_instruction_markers")
            risk_score += 15

        detector_names = list(dict.fromkeys(detector_names))
        risk_score = min(risk_score, 100)

        detected = risk_score >= self.detect_threshold

        should_block = (
            self.mode == "block"
            and risk_score >= self.block_threshold
        )

        allowed = not should_block

        if should_block:
            action = "block"
            reason = "Input blocked by scoring firewall."
        elif detected:
            action = "monitor"
            reason = "Input detected but allowed for monitoring."
        else:
            action = "allow"
            reason = "Input allowed."

        return FirewallDecision(
            allowed=allowed,
            detected=detected,
            action=action,
            risk_score=risk_score,
            detector_names=detector_names,
            reason=reason,
            features=features.to_dict(),
        )