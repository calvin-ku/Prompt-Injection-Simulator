import json
from pathlib import Path
from typing import Any, Dict, Iterable


class ECSJsonlLogger:
    """
    Writes telemetry events as newline-delimited JSON.

    TelemetryBuilder creates structured ECS/Splunk-friendly fields.
    This class only handles persistence.
    """

    def __init__(self, output_path: str = "telemetry/events.jsonl"):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def write_event(self, event: Dict[str, Any]) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event))
            file.write("\n")

    def write_events(self, events: Iterable[Dict[str, Any]]) -> None:
        with self.output_path.open("a", encoding="utf-8") as file:
            for event in events:
                file.write(json.dumps(event))
                file.write("\n")