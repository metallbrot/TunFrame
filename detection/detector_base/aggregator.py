# for windowing and aggregation by domain name or host ip
import sys
import os
import tldextract
from collections import defaultdict


from detection.detector_base.feature_extraction import safe_get

def group_by_domain(loglines:list[dict]) -> dict[str, list[dict]]:
    grouped_loglines = defaultdict(list)
    for logline in loglines:
        fqdn = safe_get(logline, "dns.qname")
        if not fqdn:
            continue
        sld = tldextract.extract(fqdn).top_domain_under_public_suffix
        if not sld:
            continue
        grouped_loglines[sld].append(logline)

    return dict(grouped_loglines)

def group_by_host(loglines:list[dict]) -> dict[str, list[dict]]:
    grouped_loglines = defaultdict(list)
    for logline in loglines:
        host_ip = safe_get(logline, "network.queryip")
        grouped_loglines[host_ip].append(logline)

    return dict(grouped_loglines)

def average_feature(loglines: list[dict], feature: callable) -> float:
    sum = 0
    for logline in loglines:
        attribute = callable(logline)
        if isinstance(attribute, (int, float)):
            sum += callable(logline)
        else:
            return -1
    return sum / len(loglines)