import time
import logging
from abc import ABC, abstractmethod
from detection.detector_base.metrics import true_positive_rate, false_positive_rate
from detection.detector_base.feature_extraction import get_registered_domain, is_response, format_bytes, query_payload_bytes, answer_payload_bytes


# Get the logger configured in main.py
logger = logging.getLogger('dns_detector')

class Detector(ABC):
    """Base class for detectors evaluated by TunFrame.

    Subclasses implement ``detect()`` and add registered domains to
    ``self.alarms``. They may override ``on_phase_reset()`` to clear internal
    state between DNSExfiltrator configurations.
    """

    def __init__(self):
        self.allowlist = set()
        self.reset(clear_allowlist=True, reset_state=False)

    @abstractmethod
    def detect(self, logline: dict):
        pass

    def on_phase_reset(self):
        """Hook for detector-specific state, called by ``reset()``.

        Override in a detector to clear internal state (windows, trackers,
        sketches) that must not carry over between DNSExfiltrator configs.
        The default does nothing.
        """

    def reset(self, clear_allowlist: bool = False, reset_state: bool = True):
        """Reset alarms, counters, runtime and leakage.

        This is the single reset API of the base class.

        * At every DNSExfiltrator config boundary ``main.py`` calls ``reset()``:
          the allowlist is kept and ``on_phase_reset()`` clears detector state.
        * After peacetime ``generate_allowlists()`` calls
          ``reset(clear_allowlist=True, reset_state=False)`` and then assigns
          the new allowlist; state learned in peacetime is kept.

        Args:
            clear_allowlist: Also clear the allowlist.
            reset_state: Call ``on_phase_reset()`` for detector-specific state.
        """
        self.start_time = None
        self.first_alarm_time = None
        self.total_process_time = 0.0
        self.processed_lines = 0
        self.detect_calls = 0
        self.tunneling_missed = 0
        self.tunneling_missed_responses = 0
        self.lv_up = 0
        self.lv_down = 0
        self.allowlisted_tunnel_lines = 0
        self.allowlisted_tunnel_queries = 0
        self.allowlisted_tunnel_responses = 0
        self.allowlisted_tunnel_lv_up = 0
        self.allowlisted_tunnel_lv_down = 0
        self.alarms = set()
        if clear_allowlist:
            self.allowlist = set()
        if reset_state:
            self.on_phase_reset()

    def process_line(self, logline: dict, istunnel: bool):
        if self.start_time is None:
            self.start_time = time.time()

        domain = get_registered_domain(logline)

        alarm_count_pre = len(self.alarms)

        if domain not in self.allowlist:
            start = time.time()
            self.detect(logline)
            timediff = time.time() - start
            self.detect_calls += 1
            
            if istunnel and domain not in self.alarms:
                if is_response(logline):
                    self.tunneling_missed_responses += 1
                    # Downlink leakage: RDATA volume of the answer records.
                    self.lv_down += answer_payload_bytes(logline)
                else:
                    self.tunneling_missed += 1
                    # Uplink leakage: full encoded payload of the query name.
                    self.lv_up += query_payload_bytes(logline)
            self.total_process_time += timediff
        elif istunnel:
            # Allowlisted tunneling traffic never reaches detect() and can never
            # raise an alarm. Account for it separately so the run stays fully
            # accounted; the detection decision itself is unchanged.
            self.allowlisted_tunnel_lines += 1
            if is_response(logline):
                self.allowlisted_tunnel_responses += 1
                self.allowlisted_tunnel_lv_down += answer_payload_bytes(logline)
            else:
                self.allowlisted_tunnel_queries += 1
                self.allowlisted_tunnel_lv_up += query_payload_bytes(logline)
        
        self.processed_lines += 1

        if len(self.alarms) > alarm_count_pre:
            color = "\033[92m" if istunnel else "\033[91m"
            logger.info(f"\n{self.__class__.__name__}: Added {color}{domain}\033[0m to alarms")

    def evaluate(self, tunneling_domains: set, all_domains: set, total_loglines: int, tunneling_queries: int,
                 global_allowlist: set, tunneling_responses: int = 0, expansion_factor: float = 1.0) -> dict:
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
            total_loglines: Number of log lines (queries and responses)
                processed in this phase.
            tunneling_queries: Number of tunneling query lines in this phase.
            global_allowlist: Global allowlist, used to report the
                detector-specific part of the allowlist.
            tunneling_responses: Number of tunneling response lines.
            expansion_factor: Encoding expansion factor of the tunnel traffic;
                ``estimated_real_traffic_up_bytes = lv_up / expansion_factor``.

        Returns:
            dict: Metrics, confusion-matrix counts and accounting counters.
        """
        expansion_factor = float(expansion_factor) if expansion_factor else 1.0

        alarms = self.alarms.difference(self.allowlist)
        logger.debug(f"num alarms: {len(alarms)}")
        
        tunneling_loglines = tunneling_queries + tunneling_responses
        if tunneling_loglines == 0:
            tunneling_domains = set()
        
        tp = alarms.intersection(tunneling_domains)
        fp = alarms.difference(tunneling_domains)
        fn = tunneling_domains.difference(tp)
        tn = all_domains.difference(tp).difference(fp).difference(fn)
        
        tpr = true_positive_rate(len(tp), len(fn))
        fpr = false_positive_rate(len(fp), len(tn))
        
        runtime = self.total_process_time
        # Average over the lines that actually reached detect(); allowlisted
        # lines are skipped before detect() and must not dilute the average.
        avg_process_time = self.total_process_time / self.detect_calls if self.detect_calls > 0 else 0.0
        
        logger.debug("\n--- Performance Metrics ---")
        logger.debug(f"Total runtime: {runtime:.3f}s")
        logger.debug(f"Avg processing time per logline: {avg_process_time*1000:.3f} ms")
        logger.debug(f"Processed loglines: {self.processed_lines}/{total_loglines} (reached detect(): {self.detect_calls})")
        
        logger.debug("\n--- Detection Metrics ---")
        logger.debug(f"Total tunnel queries seen: {tunneling_queries} (responses: {tunneling_responses})")
        logger.debug(f"Tunnel queries missed: {self.tunneling_missed} (responses: {self.tunneling_missed_responses})")
        logger.debug(f"Traffic volume down: {format_bytes(self.lv_down)}, Traffic volume up: {format_bytes(self.lv_up)}")
        if self.allowlisted_tunnel_lines:
            logger.debug(f"Allowlisted tunnel traffic (never inspected): {self.allowlisted_tunnel_queries} queries, "
                        f"{self.allowlisted_tunnel_responses} responses, up {format_bytes(self.allowlisted_tunnel_lv_up)}, "
                        f"down {format_bytes(self.allowlisted_tunnel_lv_down)}")
        logger.debug(f"Estimated real traffic volume up: {format_bytes(self.lv_up / expansion_factor)}")
        
        if alarms:
            logger.debug(f"Alarms: {alarms}")
        else:
            logger.debug("Alarms: None")
        
        logger.debug(f"Number of unique registered domains: {len(all_domains)}")
        logger.debug(f"Length Allowlist: {len(self.allowlist)}")
        logger.debug(f"Total alarms: {len(alarms)}, TP: {len(tp)} FP: {len(fp)}, TN: {len(tn)}, FN: {len(fn)}")
        
        accuracy = (len(tp) + len(tn)) / (len(tp) + len(fp) + len(tn) + len(fn)) if (len(tp) + len(fp) + len(tn) + len(fn)) > 0 else 0
        precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0
        recall = tpr
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        logger.debug(f"Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
        logger.debug(f"TPR: {tpr:.4f}, FPR: {fpr:.6f}")
        logger.debug("")
        
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
            "detect_calls": self.detect_calls,
            "total_loglines": total_loglines,
            
            # Tunneling-specific metrics
            "tunneling_loglines": tunneling_loglines,
            "tunneling_queries": tunneling_queries,
            "tunneling_responses": tunneling_responses,
            "tunneling_missed": self.tunneling_missed,
            "tunneling_missed_responses": self.tunneling_missed_responses,
            "traffic_volume_up_bytes": self.lv_up,
            "traffic_volume_down_bytes": self.lv_down,
            "allowlisted_tunnel_lines": self.allowlisted_tunnel_lines,
            "allowlisted_tunnel_queries": self.allowlisted_tunnel_queries,
            "allowlisted_tunnel_responses": self.allowlisted_tunnel_responses,
            "allowlisted_tunnel_up_bytes": self.allowlisted_tunnel_lv_up,
            "allowlisted_tunnel_down_bytes": self.allowlisted_tunnel_lv_down,
            "estimated_real_traffic_up_bytes": self.lv_up / expansion_factor,
            "expansion_factor": expansion_factor,
            
            # Domain statistics
            "total_alarms": len(alarms),
            "total_unique_domains": len(all_domains),
            "allowlist_size": len(self.allowlist),
            "tunneling_domains_count": len(tunneling_domains)
        }
