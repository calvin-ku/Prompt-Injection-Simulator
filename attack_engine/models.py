from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SuccessCondition:
    type: str
    value: Any


@dataclass(frozen=True)
class AttackDefinition:
    attack_id: str
    family: str
    delivery: str
    strategy: str
    severity: str
    mutations: List[str]
    payload_template: str
    success_condition: SuccessCondition


@dataclass(frozen=True)
class MappingEntry:
    attack_id: str
    mapped_id: str


@dataclass(frozen=True)
class TargetConfig:
    name: str
    model: str
    endpoint: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TargetResponse:
    output_text: str
    latency_ms: int
    tool_calls: List[str] = field(default_factory=list)

    detected: bool = False
    detection_mechanism: Optional[str] = None

    blocked: bool = False
    firewall_result: Dict[str, Any] = field(default_factory=dict)
    output_scrubber_result: Dict[str, Any] = field(default_factory=dict)

    error_type: Optional[str] = None
    error_message: Optional[str] = None

    raw_response: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    succeeded: bool
    success_condition_type: str
    reason: str


@dataclass
class AttackExecutionResult:
    campaign_id: str
    event_id: str
    attack_id: str
    original_payload: str
    mutated_payload: str
    mutation_chain: List[str]
    owasp_id: Optional[str]
    atlas_id: Optional[str]
    target_response: TargetResponse
    evaluation: EvaluationResult
    telemetry: Dict[str, Any]