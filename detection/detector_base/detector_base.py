import os
import sys
import time
from abc import ABC, abstractmethod

from detection.detector_base.metrics import true_positive_rate, false_positive_rate
from detection.detector_base.feature_extraction import get_registered_domain

class Detector(ABC):

    def __init__(self):
        self.start_time = None     
        self.first_alarm_time = None
        self.total_process_time = 0.0      
        self.processed_lines = 0
        self.tunneling_missed = 0
        self.alarms = set()

    @abstractmethod
    def detect(self, logline: dict):
        pass

    def process_line(self, logline: dict, istunnel: bool):
        if self.start_time is None:
            self.start_time = time.time()
        start = time.time()
        self.detect(logline)
        timediff = time.time() - start
        domain = get_registered_domain(logline)
        if istunnel and domain not in self.alarms:
            self.tunneling_missed += 1
        self.total_process_time += timediff
        self.processed_lines += 1

    def evaluate(self, tunneling_domains: set[str], allowlist: set[str], all_domains: set[str], total_loglines: int, tunneling_loglines: int) -> dict[str, float | int]:
        alarms = self.alarms.difference(allowlist)
        print(f"num alarms: {len(alarms)}")
        if tunneling_loglines == 0:
            tunneling_domains = set()
        tp = alarms.intersection(tunneling_domains)
        fp = alarms.difference(tunneling_domains)
        fn = tunneling_domains.difference(tp)
        tn = all_domains.difference(tp).difference(fp)
        tpr = true_positive_rate(len(tp), len(fn))
        fpr = false_positive_rate(len(fp), len(tn))
        
        runtime = self.total_process_time
        avg_process_time = self.total_process_time / self.processed_lines if self.processed_lines > 0 else 0.0
        
        print(f"\n--- Performance Metrics ---")
        print(f"Total runtime: {runtime:.3f}s")
        print(f"Avg processing time per logline: {avg_process_time*1000:.3f} ms")
        print(f"Processed loglines: {self.processed_lines}/{total_loglines}")
        
        print(f"\n--- Detection Metrics ---")
        print(f"Total tunnel queries seen: {tunneling_loglines}")
        print(f"Tunnel queries missed before alarm: {self.tunneling_missed}")
        missed_pct = (self.tunneling_missed / tunneling_loglines * 100) if tunneling_loglines > 0 else 0
        print(f"  ({missed_pct:.1f}% of tunnel traffic missed)")
        if alarms:
            print(f"Alarms: {alarms}")
        else:
            print(f"Alarms: None")
        print(f"Number of unique registered domains: {len(all_domains)}")
        print(f"Allowlist: {allowlist}")
        print(f"Total alarms: {len(alarms)}, TP: {len(tp)} FP: {len(fp)}, TN: {len(tn)}, FN: {len(fn)}")
        
        accuracy = (len(tp) + len(tn)) / (len(tp) + len(fp) + len(tn) + len(fn))
        precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
        recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        print(f"TPR: {tpr:.4f}, FPR: {fpr:.6f}")
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tpr": tpr,
            "fpr": fpr,
            "tp": len(tp),
            "fp": len(fp),
            "tn": len(tn),
            "fn": len(fn),
            "runtime": runtime,
            "avg_process_time_ms": avg_process_time * 1000,
            "processed_lines": self.processed_lines,
            "total_loglines": total_loglines,
            "tunneling_loglines": tunneling_loglines,
            "tunneling_missed": self.tunneling_missed,
            "tunneling_missed_pct": missed_pct
        }
