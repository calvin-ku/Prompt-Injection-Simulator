import json
import os
from typing import List, Dict
from attack_engine.mutators import PayloadMutator

class AttackGenerator:
    """
    Parses JSON taxonomies and orchestrates the fuzzing engine
    to generate the final barrage of attack vectors.
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

    def generate_campaign(self) -> List[Dict]:
        """
        Multiplies base intents using the mutation engine to create a comprehensive suite.
        """
        base_attacks = self.load_catalogs()
        campaign_payloads = []

        for attack in base_attacks:
            # Pass the base template through the mutator
            variants = PayloadMutator.generate_variants(attack["payload_template"])
            
            for variant in variants:
                # Merge the generated payload with the original telemetry tags
                attack_vector = attack.copy()
                attack_vector["mutation_strategy"] = variant["mutation_type"]
                attack_vector["fuzzed_payload"] = variant["mutated_payload"]
                
                campaign_payloads.append(attack_vector)

        return campaign_payloads

if __name__ == "__main__":
    # Run this file directly to test the generation
    generator = AttackGenerator()
    campaign = generator.generate_campaign()
    print(f"Successfully generated {len(campaign)} fuzzed attack vectors.")
    if campaign:
        print("Sample Vector:")
        print(json.dumps(campaign[0], indent=2))