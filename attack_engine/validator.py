import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from models import AttackDefinition, SuccessCondition


class CatalogValidationError(ValueError):
    pass


class CatalogValidator:
    REQUIRED_ATTACK_FIELDS = {
        "attack_id",
        "family",
        "delivery",
        "strategy",
        "severity",
        "mutations",
        "payload_template",
        "success_condition",
    }

    ALLOWED_ATTACK_FIELDS = REQUIRED_ATTACK_FIELDS

    VALID_SEVERITIES = {
        "low",
        "medium",
        "high",
        "critical",
    }

    VALID_SUCCESS_TYPES = {
        "contains",
        "regex",
        "tool_invocation",
        "data_exposure",
        "timeout",
    }

    VALID_OWASP_IDS = {
        "LLM01",
        "LLM02",
        "LLM03",
        "LLM04",
        "LLM05",
        "LLM06",
        "LLM07",
        "LLM08",
        "LLM09",
        "LLM10",
    }

    # Initial allowed ATLAS IDs used by your current catalog.
    # Expand this later into a fuller mitre_atlas_reference.json file.
    VALID_ATLAS_IDS = {
        "AML.T0024",
        "AML.T0043",
        "AML.T0051",
        "AML.T0051.000",
        "AML.T0051.001",
        "AML.T0053",
        "AML.T0054",
    }

    ATLAS_PATTERN = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")

    def __init__(self, mutator_names: Set[str]):
        self.mutator_names = mutator_names

    def load_json(self, path: str) -> dict:
        file_path = Path(path)

        if not file_path.exists():
            raise CatalogValidationError(f"File does not exist: {path}")

        try:
            with file_path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except json.JSONDecodeError as exc:
            raise CatalogValidationError(
                f"Invalid JSON in {path}: {exc}"
            ) from exc

    def parse_attacks(self, attack_catalog: dict) -> Dict[str, AttackDefinition]:
        if "attacks" not in attack_catalog:
            raise CatalogValidationError("attack_catalog.json must contain 'attacks'")

        if not isinstance(attack_catalog["attacks"], list):
            raise CatalogValidationError("'attacks' must be a list")

        parsed: Dict[str, AttackDefinition] = {}

        for raw_attack in attack_catalog["attacks"]:
            attack = self._parse_single_attack(raw_attack)

            if attack.attack_id in parsed:
                raise CatalogValidationError(
                    f"Duplicate attack_id: {attack.attack_id}"
                )

            parsed[attack.attack_id] = attack

        return parsed

    def _parse_single_attack(self, raw_attack: dict) -> AttackDefinition:
        if not isinstance(raw_attack, dict):
            raise CatalogValidationError("Each attack must be an object")

        fields = set(raw_attack.keys())

        missing = self.REQUIRED_ATTACK_FIELDS - fields
        extra = fields - self.ALLOWED_ATTACK_FIELDS

        if missing:
            raise CatalogValidationError(
                f"Attack is missing required fields: {sorted(missing)}"
            )

        if extra:
            raise CatalogValidationError(
                f"Attack contains invalid fields: {sorted(extra)}"
            )

        attack_id = raw_attack["attack_id"]

        if not isinstance(attack_id, str) or not attack_id.strip():
            raise CatalogValidationError("attack_id must be a non-empty string")

        severity = raw_attack["severity"]

        if severity not in self.VALID_SEVERITIES:
            raise CatalogValidationError(
                f"{attack_id}: invalid severity '{severity}'"
            )

        mutations = raw_attack["mutations"]

        if not isinstance(mutations, list):
            raise CatalogValidationError(
                f"{attack_id}: mutations must be a list"
            )

        for mutation in mutations:
            if mutation not in self.mutator_names:
                raise CatalogValidationError(
                    f"{attack_id}: unknown mutator '{mutation}'"
                )

        success_condition = raw_attack["success_condition"]

        if not isinstance(success_condition, dict):
            raise CatalogValidationError(
                f"{attack_id}: success_condition must be an object"
            )

        if set(success_condition.keys()) != {"type", "value"}:
            raise CatalogValidationError(
                f"{attack_id}: success_condition must contain only 'type' and 'value'"
            )

        condition_type = success_condition["type"]

        if condition_type not in self.VALID_SUCCESS_TYPES:
            raise CatalogValidationError(
                f"{attack_id}: invalid success_condition type '{condition_type}'"
            )

        return AttackDefinition(
            attack_id=attack_id,
            family=raw_attack["family"],
            delivery=raw_attack["delivery"],
            strategy=raw_attack["strategy"],
            severity=severity,
            mutations=mutations,
            payload_template=raw_attack["payload_template"],
            success_condition=SuccessCondition(
                type=success_condition["type"],
                value=success_condition["value"],
            ),
        )

    def parse_owasp_mapping(
        self,
        mapping_catalog: dict,
        attack_ids: Set[str],
    ) -> Dict[str, str]:
        return self._parse_mapping(
            mapping_catalog=mapping_catalog,
            attack_ids=attack_ids,
            id_field="owasp_id",
            valid_ids=self.VALID_OWASP_IDS,
            mapping_name="OWASP",
        )

    def parse_atlas_mapping(
        self,
        mapping_catalog: dict,
        attack_ids: Set[str],
    ) -> Dict[str, str]:
        mapping = self._parse_mapping(
            mapping_catalog=mapping_catalog,
            attack_ids=attack_ids,
            id_field="atlas_id",
            valid_ids=self.VALID_ATLAS_IDS,
            mapping_name="MITRE ATLAS",
        )

        for attack_id, atlas_id in mapping.items():
            if not self.ATLAS_PATTERN.match(atlas_id):
                raise CatalogValidationError(
                    f"{attack_id}: malformed ATLAS ID '{atlas_id}'"
                )

        return mapping

    def _parse_mapping(
        self,
        mapping_catalog: dict,
        attack_ids: Set[str],
        id_field: str,
        valid_ids: Set[str],
        mapping_name: str,
    ) -> Dict[str, str]:
        if "mappings" not in mapping_catalog:
            raise CatalogValidationError(
                f"{mapping_name} mapping file must contain 'mappings'"
            )

        mappings = mapping_catalog["mappings"]

        if not isinstance(mappings, list):
            raise CatalogValidationError(
                f"{mapping_name} mappings must be a list"
            )

        parsed: Dict[str, str] = {}

        for entry in mappings:
            if not isinstance(entry, dict):
                raise CatalogValidationError(
                    f"{mapping_name} mapping entries must be objects"
                )

            expected_fields = {"attack_id", id_field}

            if set(entry.keys()) != expected_fields:
                raise CatalogValidationError(
                    f"{mapping_name} mapping entries must contain only "
                    f"{sorted(expected_fields)}"
                )

            attack_id = entry["attack_id"]
            mapped_id = entry[id_field]

            if attack_id not in attack_ids:
                raise CatalogValidationError(
                    f"{mapping_name}: unknown attack_id '{attack_id}'"
                )

            if mapped_id not in valid_ids:
                raise CatalogValidationError(
                    f"{mapping_name}: invalid {id_field} '{mapped_id}' "
                    f"for attack '{attack_id}'"
                )

            if attack_id in parsed:
                raise CatalogValidationError(
                    f"{mapping_name}: duplicate mapping for attack '{attack_id}'"
                )

            parsed[attack_id] = mapped_id

        return parsed

    def validate_all(
        self,
        attack_catalog_path: str,
        owasp_mapping_path: str,
        atlas_mapping_path: str,
    ) -> Tuple[Dict[str, AttackDefinition], Dict[str, str], Dict[str, str]]:
        attack_catalog = self.load_json(attack_catalog_path)
        owasp_catalog = self.load_json(owasp_mapping_path)
        atlas_catalog = self.load_json(atlas_mapping_path)

        attacks = self.parse_attacks(attack_catalog)
        attack_ids = set(attacks.keys())

        owasp_mapping = self.parse_owasp_mapping(
            owasp_catalog,
            attack_ids,
        )

        atlas_mapping = self.parse_atlas_mapping(
            atlas_catalog,
            attack_ids,
        )

        return attacks, owasp_mapping, atlas_mapping