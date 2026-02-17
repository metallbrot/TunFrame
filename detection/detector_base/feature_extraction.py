import math
import re
from collections import Counter
from typing import Dict, Any, List, Tuple
import tldextract
from datetime import datetime
from fqdn import FQDN

def format_bytes(bytes_val):
    """Convert bytes to the largest appropriate unit (KB, MB, GB, TB)"""
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1000.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1000.0
    return f"{bytes_val:.2f} PB"

def json_safe_get(event, path, default=None):
    keys = path.split('.')
    current = event
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current

def get_fqdn(event: Dict) -> str:
    fqdn = json_safe_get(event, "dns.qname")
    return fqdn

def get_registered_domain(event: Dict) -> str:
    return tldextract.extract(get_fqdn(event)).top_domain_under_public_suffix

def longest_common_substring(s1: str, s2: str) -> int:
    """
    Length of longest common substring (consecutive chars).
    High value = potential subdomain reuse pattern.
    """
    m, n = len(s1), len(s2)
    if m == 0 or n == 0:
        return 0
    
    longest = 0
    lengths = [[0] * (n + 1) for _ in range(m + 1)]
    
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                lengths[i][j] = lengths[i - 1][j - 1] + 1
                longest = max(longest, lengths[i][j])
            else:
                lengths[i][j] = 0
    
    return longest


def longest_common_subsequence(s1: str, s2: str) -> int:
    """
    Length of longest common subsequence (non-consecutive, but ordered).
    """
    m, n = len(s1), len(s2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    
    return dp[m][n]


def extract_subdomain_string(event: dict) -> str:
    """
    Extract the subdomain portion of the FQDN (excluding registered domain).
    Example: 'paaanfty.tunnel.com' -> 'paaanfty'
    """
    fqdn = get_fqdn(event)
    extracted = tldextract.extract(fqdn)
    subdomain = extracted.subdomain
    domain = extracted.domain
    
    if subdomain:
        return subdomain
    return domain


def extract_subdomains_list(qname: str) -> List[str]:
    """
    Split domain into subdomains.
    Example: 'paaanfty.tunnel.com' -> ['paaanfty', 'tunnel', 'com']
    """
    split_domain = qname.strip('.').split('.')
    if len(split_domain) > 2:
        return qname.strip('.').split('.')[:-2]
    else:
        return []



def get_longest_subdomain(qname: str) -> str:
    """Return the longest subdomain (usually the leftmost for tunnels)."""
    parts = extract_subdomains_list(qname)
    return max(parts, key=len) if parts else ''


def subdomain_length(qname: str) -> int:
    """Total length of leftmost subdomain (before first dot)."""
    parts = extract_subdomains_list(qname)
    return len(parts[0]) if parts else 0


def count_max_length_subdomains(qname: str) -> int:
    """
    Count subdomains that hit DNS label length limit (63 bytes).
    Tunnels often max out to maximize bandwidth.
    """
    parts = extract_subdomains_list(qname)
    return sum(1 for part in parts if len(part) == 63)


def count_long_consonant_sequences(text: str, min_length: int = 4) -> int:
    """
    Count consecutive consonant strings >= min_length.
    High count = likely base32/base64 encoded data.
    Example: 'paaanfty' has 'nfty' (4 consonants)
    """
    consonants = 'bcdfghjklmnpqrstvwxyz'
    count = 0
    current_streak = 0
    
    for char in text.lower():
        if char in consonants:
            current_streak += 1
        else:
            if current_streak >= min_length:
                count += 1
            current_streak = 0
    
    # Check final streak
    if current_streak >= min_length:
        count += 1
    
    return count


def shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy (bits per character).
    Higher entropy = more randomness (typical for tunneling).
    """
    if not text:
        return 0.0
    
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def entropy_longest_subdomain(qname: str) -> float:
    """Entropy of the longest subdomain (usually leftmost for tunnels)."""
    longest = get_longest_subdomain(qname)
    return shannon_entropy(longest)


def entropy_full_domain(qname: str) -> float:
    """Entropy of the entire domain name (including dots)."""
    return shannon_entropy(qname)


def extract_record_type(event: Dict) -> str:
    """
    Extract DNS query type (A, AAAA, TXT, NULL, etc.).
    Tunneling often uses TXT, NULL, CNAME, MX.
    """
    return json_safe_get(event, 'dns.qtype')


def extract_ttl(event: Dict) -> int:
    """
    Extract TTL from first answer record.
    Tunneling often uses TTL=0 to avoid caching.
    """
    an_records = json_safe_get(event, 'dns.resource-records.an', [])
    if an_records and isinstance(an_records, list) and len(an_records) > 0:
        return an_records[0].get('ttl', 0)
    return 0


def extract_packet_size(event: Dict) -> int:
    """
    DNS packet size (from dns.length).
    Tunneling often has larger packets (200-300 bytes vs 50-100 for normal).
    """
    return json_safe_get(event, 'dns.length', 0)


def extract_response_time_ms(event: Dict) -> float:
    """
    Extract latency in milliseconds.
    High latency can indicate tunneling (especially relay tunnels).
    """
    latency = json_safe_get(event, 'dnstap.latency', 0)
    # Latency is often in nanoseconds or seconds, normalize to ms
    if isinstance(latency, (int, float)):
        return latency / 1_000_000 if latency > 1000 else latency
    return -1


def extract_rcode(event: Dict) -> str:
    """
    Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.).
    Tunneling usually succeeds (NOERROR).
    """
    return json_safe_get(event, 'dns.rcode', 'NOERROR')

def rfc3339ns_to_int(timestamp_str: str) -> int:
    """Convert RFC3339ns to Unix timestamp (int, sortable)"""
    dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    return int(dt.timestamp())

def extract_timestamp(event: Dict) -> str:
    """
    Extract timestamp from the event.
    Used for temporal analysis and sequencing of DNS queries.
    """
    timestamp_str = json_safe_get(event, 'dnstap.timestamp-rfc3339ns', '')
    return rfc3339ns_to_int(timestamp_str)

def is_response(event: Dict) -> bool:
   return json_safe_get(event, 'dns.flags.qr') is True


def validate_fqdn(logline: Dict) -> bool:
    fqdn = get_fqdn(logline)
    if not fqdn or not isinstance(fqdn, str):
        return False
    try:
        return FQDN(fqdn).is_valid
    except (ValueError, TypeError, UnicodeError):
        return False