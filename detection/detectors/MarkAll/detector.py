
import sys
import os
       
from detection.detector_base.detector_base import Detector
from detection.detector_base.feature_extraction import get_registered_domain

class MarkAll(Detector):

    def __init__(self):
        super().__init__()

    def detect(self, logline: dict):
        domain = get_registered_domain(logline)
        if not domain:
            return
        if domain in self.alarms:
            return
        self.alarms.add(domain)

