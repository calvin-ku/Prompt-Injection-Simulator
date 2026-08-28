import argparse
import json
import os
import ssl
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_HEC_URL = "https://localhost:8088/services/collector/event"
DEFAULT_SOURCE = "prompt-injection-simulator"
DEFAULT_SOURCETYPE = "_json"


class SplunkHECError(RuntimeError):
    """Raised when telemetry cannot be delivered to Splunk HEC."""


class SplunkHECExporter:
    """
    Export structured telemetry events to Splunk HTTP Event Collector.

    The exporter intentionally lives in the telemetry layer so attack
    generation, execution, and orchestration remain independent from Splunk.
    """

    def __init__(
        self,
        url: str,
        token: str,
        *,
        source: str = DEFAULT_SOURCE,
        sourcetype: str = DEFAULT_SOURCETYPE,
        index: Optional[str] = None,
        verify_tls: bool = True,
        timeout: float = 10.0,
    ) -> None:
        if not url:
            raise ValueError("Splunk HEC URL must not be empty.")

        if not token:
            raise ValueError("Splunk HEC token must not be empty.")

        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

        self.url = url
        self.token = token
        self.source = source
        self.sourcetype = sourcetype
        self.index = index
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _build_packet(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        packet: Dict[str, Any] = {
            "source": self.source,
            "sourcetype": self.sourcetype,
            "event": event,
        }

        if self.index:
            packet["index"] = self.index

        return packet

    def _build_ssl_context(self):
        if self.verify_tls:
            return ssl.create_default_context()

        return ssl._create_unverified_context()

    def _send_payload(self, payload: bytes) -> Dict[str, Any]:
        request = Request(
            self.url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
        )

        try:
            with urlopen(
                request,
                timeout=self.timeout,
                context=self._build_ssl_context(),
            ) as response:
                response_body = response.read().decode("utf-8")

        except HTTPError as exc:
            error_body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise SplunkHECError(
                f"Splunk HEC returned HTTP {exc.code}: "
                f"{error_body}"
            ) from exc

        except URLError as exc:
            raise SplunkHECError(
                f"Unable to connect to Splunk HEC at "
                f"{self.url}: {exc.reason}"
            ) from exc

        try:
            result = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise SplunkHECError(
                "Splunk HEC returned a non-JSON response: "
                f"{response_body!r}"
            ) from exc

        if result.get("code") != 0:
            raise SplunkHECError(
                "Splunk HEC rejected the request: "
                f"{result}"
            )

        return result

    def send_event(
        self,
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        packet = self._build_packet(event)

        payload = json.dumps(
            packet,
            separators=(",", ":"),
        ).encode("utf-8")

        return self._send_payload(payload)

    def send_events(
        self,
        events: Iterable[Dict[str, Any]],
        *,
        batch_size: int = 100,
    ) -> int:
        if batch_size <= 0:
            raise ValueError(
                "batch_size must be greater than zero."
            )

        batch: List[Dict[str, Any]] = []
        sent = 0

        for event in events:
            batch.append(event)

            if len(batch) >= batch_size:
                self._send_batch(batch)
                sent += len(batch)
                batch.clear()

        if batch:
            self._send_batch(batch)
            sent += len(batch)

        return sent

    def _send_batch(
        self,
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        packets = [
            json.dumps(
                self._build_packet(event),
                separators=(",", ":"),
            )
            for event in events
        ]

        # Splunk HEC supports multiple JSON event packets
        # within a single HTTP request.
        payload = "".join(packets).encode("utf-8")

        return self._send_payload(payload)


def load_jsonl(
    path: str,
) -> Iterable[Dict[str, Any]]:
    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Telemetry file not found: {path}"
        )

    with input_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, line in enumerate(
            file,
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line "
                    f"{line_number} of {path}."
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"Expected JSON object on line "
                    f"{line_number} of {path}."
                )

            yield event


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export Prompt Injection Simulator "
            "JSONL telemetry to Splunk HEC."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to JSONL telemetry file.",
    )

    parser.add_argument(
        "--url",
        default=DEFAULT_HEC_URL,
        help="Splunk HEC event endpoint.",
    )

    parser.add_argument(
        "--token-env",
        default="SPLUNK_HEC_TOKEN",
        help=(
            "Environment variable containing "
            "the Splunk HEC token."
        ),
    )

    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help="Splunk source metadata value.",
    )

    parser.add_argument(
        "--sourcetype",
        default=DEFAULT_SOURCETYPE,
        help="Splunk sourcetype metadata value.",
    )

    parser.add_argument(
        "--index",
        default=None,
        help=(
            "Optional Splunk index. "
            "If omitted, HEC token default is used."
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Number of events per HEC request.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds.",
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable TLS certificate verification. "
            "Useful for the local Docker Splunk instance."
        ),
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    token = os.getenv(args.token_env)

    if not token:
        parser.error(
            f"Environment variable "
            f"{args.token_env!r} is not set."
        )

    exporter = SplunkHECExporter(
        url=args.url,
        token=token,
        source=args.source,
        sourcetype=args.sourcetype,
        index=args.index,
        verify_tls=not args.insecure,
        timeout=args.timeout,
    )

    events = load_jsonl(args.input)

    sent = exporter.send_events(
        events,
        batch_size=args.batch_size,
    )

    print(
        json.dumps(
            {
                "splunk_hec_url": args.url,
                "source": args.source,
                "sourcetype": args.sourcetype,
                "events_sent": sent,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()