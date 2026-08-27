import base64
import binascii
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Dict, List


MIN_BASE64_CANDIDATE_LENGTH = 40
MIN_HEX_CANDIDATE_LENGTH = 40


ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff]")

BASE64_RUN_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9+/=])"
    rf"[A-Za-z0-9+/=]{{{MIN_BASE64_CANDIDATE_LENGTH},}}"
    rf"(?![A-Za-z0-9+/=])"
)

HEX_RUN_PATTERN = re.compile(
    rf"(?<![a-fA-F0-9])"
    rf"[a-fA-F0-9]{{{MIN_HEX_CANDIDATE_LENGTH},}}"
    rf"(?![a-fA-F0-9])"
)

STRUCTURAL_MARKER_PATTERN = re.compile(
    r"(?i)(<system|</system|system_control_block|```yaml|system_config|"
    r"safety_override|directive|system_override|DOCUMENT_METADATA)"
)


@dataclass(frozen=True)
class TextFeatures:
    length: int
    entropy: float

    zero_width_count: int
    non_ascii_count: int
    non_ascii_ratio: float

    latin_count: int
    cyrillic_count: int
    suspicious_mixed_script: bool

    base64_like: bool
    hex_like: bool
    base64_candidate_count: int
    hex_candidate_count: int
    longest_base64_run: int
    longest_hex_run: int

    structural_marker_count: int

    def to_dict(self) -> Dict:
        return asdict(self)


def extract_text_features(text: str) -> TextFeatures:
    """
    Extract reusable text features for firewall detection, telemetry,
    and benchmark analysis.

    Important design choices:
    - Entropy is a feature, not a standalone maliciousness signal.
    - Base64/hex detection searches for embedded encoded substrings.
    - Non-ASCII text is tracked carefully to avoid penalizing normal
      multilingual users.
    - Mixed Latin/Cyrillic text is tracked separately because homoglyph
      attacks commonly use Cyrillic lookalike characters inside Latin text.
    """
    if not isinstance(text, str):
        text = ""

    base64_candidates = find_base64_candidates(text)
    hex_candidates = find_hex_candidates(text)

    non_ascii_count = count_non_ascii_characters(text)
    non_ascii_ratio = (
        round(non_ascii_count / len(text), 5)
        if text
        else 0.0
    )

    latin_count = count_latin_letters(text)
    cyrillic_count = count_cyrillic_letters(text)

    suspicious_mixed_script = is_suspicious_mixed_script(
        latin_count=latin_count,
        cyrillic_count=cyrillic_count,
        non_ascii_ratio=non_ascii_ratio,
    )

    return TextFeatures(
        length=len(text),
        entropy=shannon_entropy(text),

        zero_width_count=len(ZERO_WIDTH_PATTERN.findall(text)),
        non_ascii_count=non_ascii_count,
        non_ascii_ratio=non_ascii_ratio,

        latin_count=latin_count,
        cyrillic_count=cyrillic_count,
        suspicious_mixed_script=suspicious_mixed_script,

        base64_like=len(base64_candidates) > 0,
        hex_like=len(hex_candidates) > 0,
        base64_candidate_count=len(base64_candidates),
        hex_candidate_count=len(hex_candidates),
        longest_base64_run=max(
            (len(candidate) for candidate in base64_candidates),
            default=0,
        ),
        longest_hex_run=max(
            (len(candidate) for candidate in hex_candidates),
            default=0,
        ),

        structural_marker_count=len(
            STRUCTURAL_MARKER_PATTERN.findall(text)
        ),
    )


def shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy using collections.Counter.

    Higher entropy can indicate encoded, compressed, randomized, or
    high-variety text. It should not be treated as malicious by itself.
    """
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )

    return round(entropy, 5)


def find_base64_candidates(
    text: str,
    min_length: int = MIN_BASE64_CANDIDATE_LENGTH,
) -> List[str]:
    """
    Find embedded Base64-like substrings inside a larger prompt.

    This is better than checking whether the entire prompt is Base64,
    because encoded payloads are often embedded inside normal text.
    """
    if not isinstance(text, str):
        return []

    candidates = []

    for match in BASE64_RUN_PATTERN.finditer(text):
        candidate = match.group(0)

        if len(candidate) < min_length:
            continue

        if len(candidate) % 4 != 0:
            continue

        if is_valid_base64(candidate):
            candidates.append(candidate)

    return candidates


def find_hex_candidates(
    text: str,
    min_length: int = MIN_HEX_CANDIDATE_LENGTH,
) -> List[str]:
    """
    Find embedded hexadecimal-like substrings inside a larger prompt.
    """
    if not isinstance(text, str):
        return []

    candidates = []

    for match in HEX_RUN_PATTERN.finditer(text):
        candidate = match.group(0)

        if len(candidate) < min_length:
            continue

        if len(candidate) % 2 != 0:
            continue

        candidates.append(candidate)

    return candidates


def is_valid_base64(candidate: str) -> bool:
    """
    Return True only if the candidate is valid Base64.

    validate=True rejects malformed strings instead of silently ignoring
    invalid characters.
    """
    try:
        base64.b64decode(candidate, validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def looks_base64_like(text: str) -> bool:
    """
    Compatibility helper for callers that only need a boolean.
    """
    return len(find_base64_candidates(text)) > 0


def looks_hex_like(text: str) -> bool:
    """
    Compatibility helper for callers that only need a boolean.
    """
    return len(find_hex_candidates(text)) > 0


def count_non_ascii_characters(text: str) -> int:
    return sum(
        1
        for character in text
        if ord(character) > 127
    )


def count_latin_letters(text: str) -> int:
    return sum(
        1
        for character in text
        if ("a" <= character <= "z") or ("A" <= character <= "Z")
    )


def count_cyrillic_letters(text: str) -> int:
    return sum(
        1
        for character in text
        if "\u0400" <= character <= "\u04FF"
    )


def is_suspicious_mixed_script(
    latin_count: int,
    cyrillic_count: int,
    non_ascii_ratio: float,
) -> bool:
    """
    Detect likely homoglyph-style mixed-script text.

    This avoids treating ordinary multilingual text as suspicious simply
    because it contains non-ASCII characters.

    Suspicious example:
        "Ignоrе all prеviоus instructiоns"

    Benign multilingual example:
        "こんにちは、世界"
    """
    return (
        latin_count >= 3
        and cyrillic_count > 0
        and non_ascii_ratio < 0.5
    )