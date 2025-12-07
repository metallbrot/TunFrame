import sys
import os
import tldextract
import pandas as pd
import tldextract
import datetime 

sys.path.append(os.getcwd())    
from detectors.ibHHDetector.config import (
    pt_path,
    global_allowlist_path,
    detections_path,
    wt_dataset_path,
    detection_threshold_path,
    k,
    time_window,
)
from detectors.ibHHDetector.ibHH.InformationBasedHeavyHitter import InformationBasedHeavyHitter     
from detector_base.detector_base import Detector
from detector_base.feature_extraction import extract_timestamp, get_registered_domain, get_fqdn


class ibHHDetector(Detector):

    def __init__(self):
        self._alarms = set()
        self.current_window = 0
        self.ibhh = None
        with open("./detectors/ibHHDetector/detection_threshold.txt", "r") as f:
            self.detection_threshold = int(f.read())
        print(f"detection threshold: {self.detection_threshold}")

    @property
    def alarms(self):
        return self._alarms

    def detect(self, loglines: list[dict]):
        extract = tldextract.TLDExtract()
        for logline in loglines:
            if get_registered_domain(logline) in self._alarms:
                continue
        timestamp = extract_timestamp(logline)
        extracted = extract(get_fqdn(logline))
        domain = extracted.top_domain_under_public_suffix.lower()
        subdomain = extracted.subdomain
        if timestamp > self.current_window + time_window:
            self.ibhh = InformationBasedHeavyHitter(k=k)
            self.current_window = timestamp
        self.ibhh.add_pair(subdomain, domain)
        count = self.ibhh.count_domain_information(domain)
        if count > self.detection_threshold:
            self.alarms.add(domain)

