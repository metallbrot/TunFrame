"""Helpers for DNS-collector events, used by the harness and by detectors.

The registered domain (eTLD+1) computed here is the key of ground truth,
allowlists and alarms everywhere in TunFrame. Event fields follow
DNS-collector's JSON output (``dns.qname``, ``dns.flags.qr``, ...).
"""
import functools
import hashlib
import math
import re
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
    """Return the value at dotted ``path`` (e.g. ``dns.flags.qr``) in ``event``, or ``default``."""
    keys = path.split('.')
    current = event
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current

def get_fqdn(event: Dict) -> str:
    """Return the query name (``dns.qname``) as captured, or ``None``."""
    fqdn = json_safe_get(event, "dns.qname")
    return fqdn

# Single source of truth for the eTLD+1 aggregation key. Offline (bundled PSL
# snapshot of the pinned tldextract version, no fetch, no cache) so results are
# reproducible; ICANN section only, private suffixes such as duckdns.org or
# github.io are NOT treated as public suffixes.
# Keep in sync with PSL_EXTRACT in docker/dnsexfiltrator-server/volume/dnsExfiltrator.py.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)


def normalize_name(name) -> str:
    """Return a DNS name in the canonical form used everywhere in TunFrame.

    Lowercase, surrounding whitespace and a trailing dot removed. DNS names are
    case-insensitive, so ground truth, alarms and allowlists all compare this
    form. ``None`` and non-strings become ``""``.
    """
    if not isinstance(name, str):
        return ""
    return name.strip().rstrip('.').lower()


def registered_domain(name) -> str:
    """Return the registered domain (eTLD+1, ICANN PSL) of a name, or ``""``.

    Example: ``A.b.Example.CO.uk.`` -> ``example.co.uk``. Names without a
    registrable part (``localhost``, a bare suffix) return ``""``.
    """
    ext = _EXTRACT(normalize_name(name))
    if not ext.domain or not ext.suffix:
        return ""
    return f"{ext.domain}.{ext.suffix}"


def subdomain_labels(name) -> list:
    """Return the labels left of the registered domain (``[]`` if there are none).

    Unlike the aggregation key, the labels keep their case: they carry the
    (possibly case-sensitive) payload, and features such as entropy use them.
    """
    if not isinstance(name, str):
        return []
    ext = _EXTRACT(name.strip().rstrip('.'))
    if not ext.domain or not ext.suffix or not ext.subdomain:
        return []
    return ext.subdomain.split('.')


# Letter case of the subdomain labels as the detectors receive them
# (``global.subdomain_case``). Emulates where the detectors observe DNS:
#   preserve   as captured: the case the client sent. TunFrame's collector sits
#              on the client -> resolver hop, where this is what a sensor sees
#   lowercase  every letter lowercased (a log pipeline that normalises names)
#   uppercase  every letter uppercased
#   0x20       every letter's case randomised, as seen upstream of a resolver
#              with DNS 0x20 encoding (draft-vixie-dnsext-dns0x20), e.g. at
#              the egress or authoritative side
# Only the labels left of the registered domain change; the registered domain
# keeps its case, and the eTLD+1 key is lowercased anyway (normalize_name).
SUBDOMAIN_CASES = ("preserve", "lowercase", "uppercase", "0x20")
DEFAULT_SUBDOMAIN_CASE = "preserve"


def parse_subdomain_case(value) -> str:
    """Validate ``global.subdomain_case`` and return it in canonical form.

    ``None`` means the default (``preserve``). An unquoted ``0x20`` in YAML is the
    integer 32 and is accepted as ``0x20``.

    Raises:
        ValueError: For any other value.
    """
    if value is None:
        return DEFAULT_SUBDOMAIN_CASE
    if isinstance(value, int) and not isinstance(value, bool) and value == 0x20:
        return "0x20"
    case = str(value).strip().lower()
    if case not in SUBDOMAIN_CASES:
        raise ValueError(f"global.subdomain_case must be one of {', '.join(SUBDOMAIN_CASES)} "
                         f"(got {value!r})")
    return case


def _dns0x20(text: str, seed: str) -> str:
    """Randomise the case of every ASCII letter in ``text``.

    The pattern is derived from ``seed`` (the lowercased query name), so the
    same name always gets the same case pattern: a query and its response stay
    consistent, and runs are reproducible.
    """
    bits = hashlib.shake_256(seed.encode("utf-8", "surrogatepass")).digest(len(text) // 8 + 1)
    out = []
    for i, char in enumerate(text):
        if char.isascii() and char.isalpha():
            upper = (bits[i // 8] >> (i % 8)) & 1
            char = char.upper() if upper else char.lower()
        out.append(char)
    return "".join(out)


@functools.lru_cache(maxsize=65536)
def apply_subdomain_case(name: str, case: str) -> str:
    """Return ``name`` with its subdomain labels in the given case.

    See ``SUBDOMAIN_CASES``. Names without a subdomain (apex queries, names
    without a registered domain) are returned unchanged, as is a trailing dot.
    """
    if case == "preserve":
        return name
    ext = _EXTRACT(name.rstrip('.'))
    prefix = ext.subdomain
    if not ext.domain or not ext.suffix or not prefix or not name.startswith(prefix):
        return name
    if case == "lowercase":
        cased = prefix.lower()
    elif case == "uppercase":
        cased = prefix.upper()
    else:
        cased = _dns0x20(prefix, name.rstrip('.').lower())
    return cased + name[len(prefix):]


def apply_subdomain_case_to_event(event: Dict, case: str) -> None:
    """Rewrite the event's ``dns.qname`` in place, see ``apply_subdomain_case()``."""
    if case == "preserve":
        return
    dns = event.get("dns") if isinstance(event, dict) else None
    if isinstance(dns, dict) and isinstance(dns.get("qname"), str):
        dns["qname"] = apply_subdomain_case(dns["qname"], case)


def normalize_tunneling_domains(domains) -> list:
    """Normalise and validate ``traffic.tunnel.tunneling_domains``.

    Every entry must already be a registered domain (eTLD+1), because that is
    the granularity detectors alarm on and the ground truth is compared at.

    Returns:
        list: Normalised domains, deduplicated, in configured order.

    Raises:
        ValueError: If an entry has no valid public suffix or is not an eTLD+1.
    """
    result = []
    for entry in domains or []:
        name = normalize_name(entry)
        if not _EXTRACT(name).suffix:
            raise ValueError(f"Tunneling domain '{entry}' has no valid public suffix (ICANN PSL).")
        registered = registered_domain(name)
        if registered != name:
            raise ValueError(f"Tunneling domain '{entry}' is not a registered domain (eTLD+1). "
                             f"Use '{registered}' instead.")
        if name not in result:
            result.append(name)
    return result


def _domain_list_entry(line: str) -> str:
    """Return the eTLD+1 of one domain-list line, or ``""`` if there is none.

    Supported formats: one domain per line, CSV such as Tranco's
    ``rank,domain``, tab- or space-separated columns (hosts-file style), and
    ``#`` comments. The last column that looks like a domain is used.
    """
    line = line.split('#', 1)[0].strip()
    if not line:
        return ""
    fields = [f.strip().strip('"\'') for f in re.split(r'[,;\t ]+', line) if f.strip()]
    for field in reversed(fields):
        if '.' in field and not field.replace('.', '').isdigit():
            return registered_domain(field)
    return ""


def load_domain_list(path) -> set:
    """Load a domain list (e.g. Tranco top-1M) as a set of eTLD+1 keys.

    Empty lines and ``#`` comments are skipped; entries without a registered
    domain are dropped. See ``_domain_list_entry()`` for the line formats.
    """
    domains = set()
    with open(path, 'r', encoding='utf-8', errors='replace') as file:
        for line in file:
            key = _domain_list_entry(line)
            if key:
                domains.add(key)
    return domains


def get_registered_domain(event: Dict) -> str:
    """Return the registered domain (eTLD+1) of the query name, or ``""``."""
    return registered_domain(get_fqdn(event))

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
    Example: 'paaanfty.tunnel.com' -> 'paaanfty'; 'tunnel.com' -> ''
    """
    return '.'.join(subdomain_labels(get_fqdn(event)))


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
    return sum(len(label.encode("utf-8")) for label in subdomain_labels(get_fqdn(event)) if label)


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
    """Convert an RFC 3339 timestamp to whole Unix seconds. Raises ValueError if it is empty or invalid."""
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
    """Return the capture time (``dnstap.timestamp-rfc3339ns``) in whole Unix seconds; ValueError if missing."""
    timestamp_str = json_safe_get(event, 'dnstap.timestamp-rfc3339ns', '')
    return rfc3339ns_to_int(timestamp_str)

def extract_type(event: Dict) -> str:
    """Return the query *class* (``dns.qclass``, usually ``IN``); for the record type use ``extract_record_type()``."""
    return json_safe_get(event, 'dns.qclass')

def extract_query_ip(event: Dict) -> str:
    """Return the client address that sent the query (``network.query-ip``)."""
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
    """True for a response (``dns.flags.qr``), False for a query."""
    return json_safe_get(event, 'dns.flags.qr') is True


def validate_fqdn(logline: Dict) -> bool:
    """True if the query name is a syntactically valid FQDN (``fqdn`` package)."""
    fqdn = get_fqdn(logline)
    if not fqdn or not isinstance(fqdn, str):
        return False
    try:
        return FQDN(fqdn).is_valid
    except (ValueError, TypeError, UnicodeError):
        return False