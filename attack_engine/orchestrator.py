import time
from typing import Dict
from attack_engine.generator import AttackGenerator

class Orchestrator:
    """
    Command & Control (C2) engine for the adversarial benchmark.
    Fires the generated dataset at the target application and 
    computes enterprise security metrics (FPR, F1, Recall).
    """
    def __init__(self):
        self.generator = AttackGenerator()

    def execute_campaign(self) -> None:
        print("Initializing Attack Generator...")
        attacks, benign = self.generator.generate_dataset(attack_target=2500, benign_target=2500)
        dataset = attacks + benign
        
        print(f"Loaded {len(dataset):,} samples. Booting evaluation engine...\n")
        
        # Confusion Matrix
        metrics = {"TP": 0, "FN": 0, "TN": 0, "FP": 0}

        start_time = time.time()

        # SIMULATED TARGET ENDPOINT (To be replaced by the real defense_pipeline next)
        import random
        for sample in dataset:
            is_attack = sample["is_malicious"]
            
            # MOCK FIREWALL LOGIC: Let's pretend our current firewall catches 82% of attacks, 
            # but accidentally blocks 6% of normal users (False Positives).
            if is_attack:
                blocked_by_firewall = random.random() < 0.82 
            else:
                blocked_by_firewall = random.random() < 0.06 

            # Tally the Confusion Matrix
            if is_attack and blocked_by_firewall:
                metrics["TP"] += 1      # Attack successfully blocked
            elif is_attack and not blocked_by_firewall:
                metrics["FN"] += 1      # Attack bypassed firewall
            elif not is_attack and not blocked_by_firewall:
                metrics["TN"] += 1      # Normal user allowed
            elif not is_attack and blocked_by_firewall:
                metrics["FP"] += 1      # Normal user blocked (False Positive)

        execution_time = time.time() - start_time
        self._print_report(metrics, execution_time)

    def _print_report(self, metrics: Dict[str, int], execution_time: float) -> None:
        tp, fn, tn, fp = metrics["TP"], metrics["FN"], metrics["TN"], metrics["FP"]
        
        # Prevent division by zero
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print("="*55)
        print("ADVERSARIAL BENCHMARK REPORT")
        print("="*55)
        print(f" Execution Time:       {execution_time:.2f} seconds")
        print(f" Total Vectors Tested: {tp+fn+tn+fp:,}")
        print("-" * 55)
        print(" CONFUSION MATRIX")
        print(f"   [TP] Attacks Blocked:           {tp:,}")
        print(f"   [FN] Attacks Bypassed (Misses): {fn:,}")
        print(f"   [TN] Benign Allowed:            {tn:,}")
        print(f"   [FP] Benign Blocked (Friction): {fp:,}")
        print("-" * 55)
        print(" PERFORMANCE METRICS")
        print(f"   Recall (Detection Rate): {recall*100:.1f}%")
        print(f"   Precision:               {precision*100:.1f}%")
        print(f"   F1 Score:                {f1_score*100:.1f}%")
        print(f"   False Positive Rate:     {fpr*100:.1f}%")
        print("="*55)

if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.execute_campaign()