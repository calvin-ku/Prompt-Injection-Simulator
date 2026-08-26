import json
import os
import random
from typing import List, Dict, Tuple
from attack_engine.mutators import PayloadMutator

class AttackGenerator:
    """
    Parses JSON taxonomies and synthesizes large-scale evaluation datasets
    with advanced mutation vectors and benign baseline controls.
    """

    def __init__(self, catalog_dir: str = "attack_catalog"):
        self.catalog_dir = catalog_dir

    def load_catalogs(self) -> List[Dict]:
        """Loads all base intents from the JSON catalogs."""
        base_attacks = []
        if not os.path.exists(self.catalog_dir):
            print(f"Error: Directory {self.catalog_dir} not found.")
            return base_attacks
            
        for filename in os.listdir(self.catalog_dir):
            if filename.endswith(".json"):
                filepath = os.path.join(self.catalog_dir, filename)
                with open(filepath, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                    base_attacks.extend(data.get("attacks", []))
        return base_attacks

    def generate_dataset(self, attack_target: int = 2500, benign_target: int = 2500) -> Tuple[List[Dict], List[Dict]]:
        """
        Generates a balanced evaluation dataset with thousands of samples.
        """
        base_attacks = self.load_catalogs()
        if not base_attacks:
            return [], []

        attacks_generated = []
        strategies = [
            ("baseline", lambda x: x),
            ("base64", PayloadMutator.base64_encode),
            ("hex", PayloadMutator.hex_encode),
            ("rot13", PayloadMutator.rot13_encode),
            ("leetspeak", PayloadMutator.leetspeak),
            ("unicode_homoglyphs", PayloadMutator.unicode_homoglyphs),
            ("xml_delimiters", PayloadMutator.xml_delimiters),
            ("yaml_spoofing", PayloadMutator.structured_yaml_spoofing),
            ("few_shot_jailbreak", PayloadMutator.few_shot_jailbreak),
            ("hypothetical_framing", PayloadMutator.hypothetical_framing),
            ("token_splitting", PayloadMutator.token_splitting),
            ("chained_mutation_d2", lambda x: PayloadMutator.apply_chain(x, depth=2)),
            ("chained_mutation_d3", lambda x: PayloadMutator.apply_chain(x, depth=3))
        ]

        count = 0
        while len(attacks_generated) < attack_target:
            base = random.choice(base_attacks)
            strat_name, strat_fn = random.choice(strategies)
            
            prefix = random.choice(["", *PayloadMutator.PREFIX_NOISE])
            suffix = random.choice(["", *PayloadMutator.SUFFIX_NOISE])
            
            raw_payload = f"{prefix}{base['payload_template']}{suffix}".strip()
            mutated_payload = strat_fn(raw_payload)

            attacks_generated.append({
                "sample_id": f"ATK-{count+1:05d}",
                "is_malicious": True,
                "attack_id": base["attack_id"],
                "family": base["family"],
                "owasp": base["owasp"],
                "atlas": base["atlas"],
                "severity": base["severity"],
                "mutation_strategy": strat_name,
                "prompt": mutated_payload,
                "success_condition": base["success_condition"]
            })
            count += 1

        benign_generated = PayloadMutator.generate_benign_samples(benign_target)
        return attacks_generated, benign_generated

if __name__ == "__main__":
    generator = AttackGenerator()
    attacks, benign = generator.generate_dataset(attack_target=2500, benign_target=2500)
    print(f"Enterprise Evaluation Dataset Generated:")
    print(f"  - Adversarial Attack Vectors: {len(attacks):,}")
    print(f"  - Benign Baseline Prompts:   {len(benign):,}")
    print(f"  - Total Benchmark Suite:     {len(attacks) + len(benign):,} samples")