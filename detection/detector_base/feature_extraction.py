import math
import re
from collections import Counter
from typing import Dict, Any, List, Tuple
import tldextract

def safe_get(event, path, default=''):
    keys = path.split('.')
    current = event
    for key in keys:
        current = current.get(key, {})
    return current if isinstance(current, str) else default

def get_fqdn(event: Dict) -> str:
    fqdn = safe_get(event, "dns.qname", '')
    return fqdn

def get_registered_domain(event: Dict) -> str:
    return tldextract.extract(get_fqdn(event)).top_domain_under_public_suffix


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Compute Levenshtein distance between two strings.
    Useful for comparing subdomain to known legit patterns.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def jaro_distance(s1: str, s2: str) -> float:
    """
    Compute Jaro distance (0 = no match, 1 = exact match).
    Better for typo detection than Levenshtein.
    """
    if s1 == s2:
        return 1.0
    
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    
    match_distance = max(len1, len2) // 2 - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    
    matches = 0
    transpositions = 0
    
    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break
    
    if matches == 0:
        return 0.0
    
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    
    return (matches / len1 + matches / len2 + 
            (matches - transpositions / 2) / matches) / 3


def jaro_winkler_distance(s1: str, s2: str, p: float = 0.1) -> float:
    """
    Jaro-Winkler: Jaro + bonus for common prefix (better for domain names).
    """
    jaro = jaro_distance(s1, s2)
    
    # Find common prefix length (max 4)
    prefix = 0
    for i in range(min(len(s1), len(s2), 4)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    
    return jaro + (prefix * p * (1 - jaro))


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


def extract_subdomains(qname: str) -> List[str]:
    """
    Split domain into subdomains.
    Example: 'paaanfty.tunnel.com' -> ['paaanfty', 'tunnel', 'com']
    """
    split_domain = qname.strip('.').split('.')
    if len(split_domain) > 2:
        return qname.strip('.').split('.')[:-2]
    else:
        return None


def get_longest_subdomain(qname: str) -> str:
    """Return the longest subdomain (usually the leftmost for tunnels)."""
    parts = extract_subdomains(qname)
    return max(parts, key=len) if parts else ''


def subdomain_length(qname: str) -> int:
    """Total length of leftmost subdomain (before first dot)."""
    parts = extract_subdomains(qname)
    return len(parts[0]) if parts else 0


def count_max_length_subdomains(qname: str) -> int:
    """
    Count subdomains that hit DNS label length limit (63 bytes).
    Tunnels often max out to maximize bandwidth.
    """
    parts = extract_subdomains(qname)
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
    return safe_get(event, 'dns.qtype')


def extract_ttl(event: Dict) -> int:
    """
    Extract TTL from first answer record.
    Tunneling often uses TTL=0 to avoid caching.
    """
    an_records = safe_get(event, 'dns.resource-records.an', [])
    if an_records and isinstance(an_records, list) and len(an_records) > 0:
        return an_records[0].get('ttl', 0)
    return 0


def extract_packet_size(event: Dict) -> int:
    """
    DNS packet size (from dns.length).
    Tunneling often has larger packets (200-300 bytes vs 50-100 for normal).
    """
    return safe_get(event, 'dns.length', 0)


def extract_response_time_ms(event: Dict) -> float:
    """
    Extract latency in milliseconds.
    High latency can indicate tunneling (especially relay tunnels).
    """
    latency = safe_get(event, 'dnstap.latency', 0)
    # Latency is often in nanoseconds or seconds, normalize to ms
    if isinstance(latency, (int, float)):
        return latency / 1_000_000 if latency > 1000 else latency
    return -1


def extract_rcode(event: Dict) -> str:
    """
    Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.).
    Tunneling usually succeeds (NOERROR).
    """
    return safe_get(event, 'dns.rcode', 'NOERROR')


def extract_timestamp(event: Dict) -> str:
    """
    Extract timestamp from the event.
    Used for temporal analysis and sequencing of DNS queries.
    """
    return safe_get(event, 'dnstap.timestamp-rfc3339ns', '')
