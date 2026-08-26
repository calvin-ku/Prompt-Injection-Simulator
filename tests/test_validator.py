import json

import pytest

from attack_engine.mutators import PayloadMutator
from attack_engine.validator import CatalogValidationError, CatalogValidator


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_validator_accepts_valid_catalog(tmp_path):
    attack_catalog = {
        "catalog_name": "Enterprise LLM Attack Engine Catalog",
        "version": "1.0.0",
        "attacks": [
            {
                "attack_id": "ATTACK-TEST-01",
                "family": "prompt_injection",
                "delivery": "direct",
                "strategy": "instruction_override",
                "severity": "critical",
                "mutations": ["base64", "homoglyph"],
                "payload_template": "test",
                "success_condition": {
                    "type": "contains",
                    "value": "test",
                },
            }
        ],
    }

    owasp_mapping = {
        "mapping_name": "OWASP Mapping",
        "version": "1.0.0",
        "mappings": [
            {
                "attack_id": "ATTACK-TEST-01",
                "owasp_id": "LLM01",
            }
        ],
    }

    atlas_mapping = {
        "mapping_name": "MITRE ATLAS Mapping",
        "version": "1.0.0",
        "mappings": [
            {
                "attack_id": "ATTACK-TEST-01",
                "atlas_id": "AML.T0051",
            }
        ],
    }

    attack_path = tmp_path / "attack_catalog.json"
    owasp_path = tmp_path / "owasp_mapping.json"
    atlas_path = tmp_path / "mitre_atlas_mapping.json"

    write_json(attack_path, attack_catalog)
    write_json(owasp_path, owasp_mapping)
    write_json(atlas_path, atlas_mapping)

    mutator = PayloadMutator(seed=123)

    validator = CatalogValidator(
        mutator_names=set(mutator.registry.keys())
    )

    attacks, owasp, atlas = validator.validate_all(
        str(attack_path),
        str(owasp_path),
        str(atlas_path),
    )

    assert "ATTACK-TEST-01" in attacks
    assert owasp["ATTACK-TEST-01"] == "LLM01"
    assert atlas["ATTACK-TEST-01"] == "AML.T0051"


def test_validator_rejects_unknown_mutator(tmp_path):
    attack_catalog = {
        "catalog_name": "Enterprise LLM Attack Engine Catalog",
        "version": "1.0.0",
        "attacks": [
            {
                "attack_id": "ATTACK-TEST-01",
                "family": "prompt_injection",
                "delivery": "direct",
                "strategy": "instruction_override",
                "severity": "critical",
                "mutations": ["does_not_exist"],
                "payload_template": "test",
                "success_condition": {
                    "type": "contains",
                    "value": "test",
                },
            }
        ],
    }

    mutator = PayloadMutator(seed=123)

    validator = CatalogValidator(
        mutator_names=set(mutator.registry.keys())
    )

    with pytest.raises(CatalogValidationError):
        validator.parse_attacks(attack_catalog)