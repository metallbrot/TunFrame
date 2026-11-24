import time
import logging
from abc import ABC, abstractmethod
from detection.detector_base.metrics import true_positive_rate, false_positive_rate
from detection.detector_base.feature_extraction import get_registered_domain, is_response, extract_record_type, format_bytes, query_payload_bytes
from main import CONFIG_PATH, load_config, cfg_safe_get

# Get the logger configured in main.py
logger = logging.getLogger('dns_detector')

class Detector(ABC):
    def __init__(self):
        self.start_time = None
        self.first_alarm_time = None
        self.total_process_time = 0.0
        self.processed_lines = 0
        self.tunneling_missed = 0
        self.lv_up = 0
        self.lv_down = 0
        self.allowlist = set()
        self.alarms = set()

    @abstractmethod
    def detect(self, logline: dict):
        pass

    def full_reset(self):
        self.start_time = None
        self.first_alarm_time = None
        self.total_process_time = 0.0
        self.processed_lines = 0
        self.tunneling_missed = 0
        self.lv_up = 0
        self.lv_down = 0
        self.allowlist = set()
        self.alarms = set()

    def phase_reset(self):
        self.start_time = None
        self.first_alarm_time = None
        self.total_process_time = 0.0
        self.processed_lines = 0
        self.tunneling_missed = 0
        self.lv_up = 0
        self.lv_down = 0
        self.alarms = set()


    def process_line(self, logline: dict, istunnel: bool):
        if self.start_time is None:
            self.start_time = time.time()

        domain = get_registered_domain(logline)

        alarm_count_pre = len(self.alarms)

        if domain not in self.allowlist:
            start = time.time()
            self.detect(logline)
            timediff = time.time() - start
            
            if istunnel and domain not in self.alarms:
                self.tunneling_missed += 1
                #TODO: add more Record Types
                if is_response(logline) and extract_record_type(logline) == 'A':
                    self.lv_down += 4
                elif not is_response(logline):
                    # Uplink leakage: full encoded payload of the query name.
                    self.lv_up += query_payload_bytes(logline)
            self.total_process_time += timediff
        
        self.processed_lines += 1

        if len(self.alarms) > alarm_count_pre:
            # Color code: green for tunneling domains, red for false positives
            if istunnel:
                # Tunneling domain (true positive) - green
                logger.info(f"\n{self.__class__.__name__}: Added \033[92m{domain}\033[0m to alarms")
            else:
                # Non-tunneling domain (false positive) - red
                logger.info(f"\n{self.__class__.__name__}: Added \033[91m{domain}\033[0m to alarms")

    def evaluate(self, tunneling_domains: set, all_domains: set, total_loglines: int, tunneling_loglines: int, global_allowlist: set) -> dict:
        """Compute domain-level detection metrics for the finished phase.

        Every registered domain in ``all_domains`` falls into exactly one of the
        four confusion-matrix classes:

        * TP: alarmed tunneling domains.
        * FP: alarmed domains that are not tunneling domains.
        * FN: tunneling domains without an alarm.
        * TN: all remaining domains, i.e. ``all_domains - TP - FP - FN``.

        Args:
            tunneling_domains: Tunneling domains actually seen in this phase.
            all_domains: Registered domains seen in this phase.
            total_loglines: Number of log lines processed in this phase.
            tunneling_loglines: Number of tunneling log lines in this phase.
            global_allowlist: Global allowlist, used to report the
                detector-specific part of the allowlist.

        Returns:
            dict: Metrics, confusion-matrix counts and accounting counters.
        """
        cfg = load_config(CONFIG_PATH)
        expansion_factor = cfg_safe_get(cfg, ['traffic', 'tunnel', 'expansion_factor'], 1)
        
        alarms = self.alarms.difference(self.allowlist)
        logger.info(f"num alarms: {len(alarms)}")
        
        if tunneling_loglines == 0:
            tunneling_domains = set()
        
        tp = alarms.intersection(tunneling_domains)
        fp = alarms.difference(tunneling_domains)
        fn = tunneling_domains.difference(tp)
        tn = all_domains.difference(tp).difference(fp).difference(fn)
        
        tpr = true_positive_rate(len(tp), len(fn))
        fpr = false_positive_rate(len(fp), len(tn))
        
        runtime = self.total_process_time
        avg_process_time = self.total_process_time / self.processed_lines if self.processed_lines > 0 else 0.0
        
        logger.info("\n--- Performance Metrics ---")
        logger.info(f"Total runtime: {runtime:.3f}s")
        logger.info(f"Avg processing time per logline: {avg_process_time*1000:.3f} ms")
        logger.info(f"Processed loglines: {self.processed_lines}/{total_loglines}")
        
        logger.info(f"\n--- Detection Metrics ---")
        logger.info(f"Total tunnel queries seen: {tunneling_loglines}")
        logger.info(f"Tunnel queries missed: {self.tunneling_missed}")
        logger.info(f"Traffic volume down: {format_bytes(self.lv_down)}, Traffic volume up: {format_bytes(self.lv_up)}")
        logger.info(f"Estimated real traffic volume up: {format_bytes(self.lv_up / expansion_factor)}")
        
        if alarms:
            logger.info(f"Alarms: {alarms}")
        else:
            logger.info("Alarms: None")
        
        logger.info(f"Number of unique registered domains: {len(all_domains)}")
        logger.info(f"Length Allowlist: {len(self.allowlist)}")
        logger.info(f"Total alarms: {len(alarms)}, TP: {len(tp)} FP: {len(fp)}, TN: {len(tn)}, FN: {len(fn)}")
        
        accuracy = (len(tp) + len(tn)) / (len(tp) + len(fp) + len(tn) + len(fn)) if (len(tp) + len(fp) + len(tn) + len(fn)) > 0 else 0
        precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
        recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        logger.info(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        logger.info(f"TPR: {tpr:.4f}, FPR: {fpr:.6f}")
        logger.info("")
        
        return {
            # Meta information
            "detector_name": self.__class__.__name__,
            
            # Classification metrics
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tpr": tpr,
            "fpr": fpr,
            
            # Confusion matrix values
            "tp": len(tp),
            "fp": len(fp),
            "tn": len(tn),
            "fn": len(fn),
            
            # Detailed alarm information
            "alarms_raised": list(alarms),
            "true_positives_list": list(tp),
            "false_positives_list": list(fp),
            "false_negatives_list": list(fn),
            "tunneling_domains": list(tunneling_domains),
            "unique_allowlist": list(self.allowlist - global_allowlist),
            # Performance metrics
            "runtime": runtime,
            "avg_process_time_ms": avg_process_time * 1000,
            "processed_lines": self.processed_lines,
            "total_loglines": total_loglines,
            
            # Tunneling-specific metrics
            "tunneling_loglines": tunneling_loglines,
            "tunneling_missed": self.tunneling_missed,
            "traffic_volume_up_bytes": self.lv_up,
            "traffic_volume_down_bytes": self.lv_down,
            "estimated_real_traffic_up_bytes": self.lv_up / expansion_factor,
            
            # Domain statistics
            "total_alarms": len(alarms),
            "total_unique_domains": len(all_domains),
            "allowlist_size": len(self.allowlist),
            "tunneling_domains_count": len(tunneling_domains)
        }
