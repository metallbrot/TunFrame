import math
from collections import Counter
from typing import Dict
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

def normalize_domain(domain) -> str:
    """Return a domain in the canonical form used everywhere in TunFrame.

    Lowercase, surrounding whitespace and a trailing dot removed. DNS names are
    case-insensitive, so ground truth, alarms and allowlists all compare this
    form.
    """
    return str(domain or "").strip().rstrip(".").lower()


def registered_domain_of(name) -> str:
    """Return the normalized registered domain of a domain name ('' if none)."""
    return normalize_domain(tldextract.extract(normalize_domain(name)).top_domain_under_public_suffix)


def get_registered_domain(event: Dict) -> str:
    """Return the normalized (lowercase) registered domain of the query name."""
    return registered_domain_of(get_fqdn(event))

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


def query_payload_bytes(event: Dict) -> int:
    """Return the size of the encoded payload carried in a query name.

    The payload is every label left of the registered domain, counted in bytes
    without the separating dots. Example: ``seq.abcdef.tunnel.com`` carries
    ``len("seq") + len("abcdef") = 9`` bytes. Apex queries carry 0 bytes.

    Args:
        event: Parsed DNS-collector event.

    Returns:
        int: Payload size in bytes.
    """
    fqdn = get_fqdn(event)
    if not fqdn:
        return 0
    subdomain = tldextract.extract(fqdn).subdomain
    return sum(len(label.encode("utf-8")) for label in subdomain.split(".") if label)


# RDATA wire sizes of fixed-size record types, in bytes.
_FIXED_RDATA_BYTES = {"A": 4, "AAAA": 16}
# Record types whose RDATA is a single domain name.
_NAME_RDATA_TYPES = {"CNAME", "NS", "PTR", "DNAME"}


def _name_wire_bytes(name: str) -> int:
    """Wire size of a domain name: one length octet per label plus the root octet."""
    labels = [label for label in str(name).strip(".").split(".") if label]
    return sum(len(label.encode("utf-8")) + 1 for label in labels) + 1


def answer_payload_bytes(event: Dict) -> int:
    """Return the RDATA volume carried by the answer section of a response.

    Sizes per answer record:

    * A: 4 bytes, AAAA: 16 bytes.
    * CNAME, NS, PTR, DNAME: wire size of the target name.
    * MX: 2 bytes preference plus the wire size of the exchange name.
    * Fallback for every other type (TXT, SVCB, NULL, ...): the UTF-8 byte
      length of DNS-collector's textual ``rdata``. This approximates the
      payload and ignores length octets.

    Responses without answer records (for example NXDOMAIN) carry 0 bytes.

    Args:
        event: Parsed DNS-collector event.

    Returns:
        int: Answer payload in bytes.
    """
    answers = json_safe_get(event, "dns.resource-records.an", []) or []
    total = 0
    for rr in answers:
        if not isinstance(rr, dict):
            continue
        rtype = str(rr.get("rdatatype", "")).upper()
        rdata = rr.get("rdata", "")
        if rtype in _FIXED_RDATA_BYTES:
            total += _FIXED_RDATA_BYTES[rtype]
        elif rtype in _NAME_RDATA_TYPES:
            total += _name_wire_bytes(rdata)
        elif rtype == "MX":
            parts = str(rdata).split()
            total += 2 + _name_wire_bytes(parts[-1] if parts else "")
        else:
            total += len(str(rdata).encode("utf-8"))
    return total


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

def extract_timestamp_date(event: Dict) -> datetime:
    """
    Extract timestamp from the event.
    Used for temporal analysis and sequencing of DNS queries.
    """
    timestamp_str = json_safe_get(event, 'dnstap.timestamp-rfc3339ns', '')
    return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

def extract_timestamp(event: Dict) -> int:
    timestamp_str = json_safe_get(event, 'dnstap.timestamp-rfc3339ns', '')
    return rfc3339ns_to_int(timestamp_str)

def extract_type(event: Dict) -> str:
    return json_safe_get(event, 'dns.qclass')

def extract_query_ip(event: Dict) -> str:
    return json_safe_get(event, 'network.query-ip')

def get_txt_content(logline: dict) -> list:
    """Extract TXT record data from a DNS response."""
    txt_records = []
    for rr in json_safe_get(logline, "dns.resource-records.an", []) or []:
        if not isinstance(rr, dict) or str(rr.get("rdatatype", "")).upper() != "TXT":
            continue
        rdata = rr.get("rdata", "")
        if isinstance(rdata, list):
            txt_records.extend(rdata)
        elif rdata:
            txt_records.append(rdata)
    return txt_records

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