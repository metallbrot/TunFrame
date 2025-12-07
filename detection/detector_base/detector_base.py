import os
import sys
from abc import ABC, abstractmethod

sys.path.append(os.getcwd())
from detector_base.metrics import true_positive_rate, false_positive_rate

class Detector:

    @property
    @abstractmethod
    def alarms(self):
        pass

    @abstractmethod
    def detect(self, loglines: list[dict]) -> list[str]:
        """Detect tunneling and return list of domains marked as tunneling"""
        pass

    def evaluate(self, tunnel_domains: {str}, allowlist: {str}, all_domains:{str}) -> dict[str, int]:
        """Evaluate performance metrics of detection method"""
        alarms = self.alarms
        alarms = alarms.difference(allowlist)
        print(f"num alarms: {len(alarms)}")
        #write_list_to_file(alarms_path, list(alarms))
        tp = alarms.intersection(tunnel_domains)
        fp = alarms.difference(tunnel_domains)
        fn = tunnel_domains.difference(tp)
        tn = all_domains.difference(tp).difference(fp)
        tpr = true_positive_rate(len(tp), len(fn))
        fpr = false_positive_rate(len(fp), len(tn))
        print(f"Alarms: {alarms}")
        print(f"All domains: {all_domains}")
        print(f"Allowlist: {allowlist}")
        print(f"Total alarms: {len(alarms)}, TP: {len(tp)} FP: {len(fp)}, TN: {len(tn)}, FN: {len(fn)}")
        accuracy = (len(tp) + len(tn)) / (len(tp) + len(fp) + len(tn) + len(fn))
        precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
        recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        print(f"Accuracy: {accuracy}, Precision: {precision}, Recall: {recall}, F1: {f1}")
        print(f"TPR: {tpr}, FPR: {fpr}")
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
            "fn": len(fn)
        }