import math
import json
import datetime
from collections import Counter, deque
from typing import Dict, Optional

class SecurityTrieNode:
    """Node structure for the Aho-Corasick Automaton."""
    def __init__(self):
        self.children: Dict[str, 'SecurityTrieNode'] = {}
        self.fail: Optional['SecurityTrieNode'] = None  # The Aho-Corasick failure link
        self.is_terminal: bool = False
        self.signature_id: Optional[str] = None

class InputValidationFirewall:
    def __init__(self):
        self.root = SecurityTrieNode()
        self.entropy_threshold = 4.8  
        
        self.signatures = {
            "ignore previous instructions": "TX-01",
            "disregard all prior": "TX-01",
            "system override": "TX-01",
            "developer mode": "TX-02",
            "unconstrained terminal": "TX-02"
        }
        self._build_trie()
        self._build_failure_links() # Initialize the Aho-Corasick pointers

    def _build_trie(self):
        """Constructs the base multiway trie graph."""
        for signature, sig_id in self.signatures.items():
            node = self.root
            for char in signature.lower():
                if char not in node.children:
                    node.children[char] = SecurityTrieNode()
                node = node.children[char]
            node.is_terminal = True
            node.signature_id = sig_id

    def _build_failure_links(self):
        """
        Uses Breadth-First Search (BFS) to construct failure links.
        This upgrades the Trie into a true Aho-Corasick automaton for O(n) scanning.
        """
        queue = deque()
        
        # Step 1: Set failure links for depth-1 nodes to the root
        for char, node in self.root.children.items():
            node.fail = self.root
            queue.append(node)
            
        # Step 2: BFS to set failure links for the rest of the tree
        while queue:
            current_node = queue.popleft()
            
            for char, child_node in current_node.children.items():
                queue.append(child_node)
                
                # Trace back the failure link of the parent
                fail_state = current_node.fail
                while fail_state is not None and char not in fail_state.children:
                    fail_state = fail_state.fail
                
                # Set the failure link
                if fail_state is None:
                    child_node.fail = self.root
                else:
                    child_node.fail = fail_state.children[char]
                    
                # Inherit terminal status from failure links (Dictionary links)
                # This ensures we catch embedded substrings (e.g., if "override" is bad, and we matched "system override")
                if child_node.fail.is_terminal and not child_node.is_terminal:
                    child_node.is_terminal = True
                    child_node.signature_id = child_node.fail.signature_id

    def calculate_entropy(self, text: str) -> float:
        """Calculates Shannon Entropy to detect obfuscated payloads (TX-03)."""
        if not text:
            return 0.0
        
        frequencies = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy

    def scan_trie(self, text: str) -> Optional[str]:
        """
        True Aho-Corasick linear scan O(n).
        No nested loops. Instantly jumps via failure links if a character sequence breaks.
        """
        text = text.lower()
        current = self.root
        
        for char in text:
            # If there's no match, follow the failure links backwards
            while current is not None and char not in current.children:
                current = current.fail
                
            # If we traced all the way back to None, reset to root
            if current is None:
                current = self.root
                continue
                
            # Move to the matched child node
            current = current.children[char]
            
            # If this state is terminal, we found a malicious payload
            if current.is_terminal:
                return current.signature_id
                
        return None

    def _log_to_siem(self, payload: str, telemetry: dict, threat_type: str, reason: str):
        """Formats blocked attacks into an ECS-compliant JSON log for SIEM ingestion."""
        ecs_log = {
            "@timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event": {
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["denied"]
            },
            "threat": {
                "tactic": "Prompt Injection",
                "technique": threat_type,
                "flagged_vector": telemetry["flagged_vector"]
            },
            "rule": {
                "name": reason,
                "entropy_score": telemetry["entropy_score"]
            },
            "payload": payload
        }
        
        with open("siem_alerts.json", "a") as log_file:
            log_file.write(json.dumps(ecs_log) + "\n")

    def evaluate_prompt(self, user_prompt: str) -> dict:
        """Multi-stage evaluation pipeline acting as the LLM middleware."""
        prompt_entropy = self.calculate_entropy(user_prompt)

        # Stage 1: Entropy Analysis
        if prompt_entropy > self.entropy_threshold:
            telemetry = {"entropy_score": round(prompt_entropy, 2), "flagged_vector": "TX-03"}
            self._log_to_siem(user_prompt, telemetry, "Data Obfuscation", "High Entropy Detected")
            return {
                "status": "BLOCKED",
                "reason": "High Entropy Detected (Potential Obfuscation)",
                "telemetry": telemetry
            }

        # Stage 2: Aho-Corasick Automaton Scan
        trie_match = self.scan_trie(user_prompt)
        if trie_match:
            telemetry = {"entropy_score": round(prompt_entropy, 2), "flagged_vector": trie_match}
            self._log_to_siem(user_prompt, telemetry, "Signature Match", f"Adversarial Pattern ({trie_match})")
            return {
                "status": "BLOCKED",
                "reason": f"Adversarial Signature Match ({trie_match})",
                "telemetry": telemetry
            }

        return {
            "status": "CLEARED",
            "reason": "Passed all defensive checks",
            "telemetry": {"entropy_score": round(prompt_entropy, 2), "flagged_vector": None}
        }