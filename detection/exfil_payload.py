"""Exact uplink payload of DNSExfiltrator traffic.

The DNSExfiltrator client (``docker/dnsexfiltrator-client``) sends three kinds
of queries to the tunnel domain:

``init``      ``<part of the init>.<domain>``: the base32map-encoded text
              ``<encoding number>|<file size>|``, split over several queries when
              it is longer than ``label_max_size``. No file data, but it tells
              the size of the transferred (zipped, encrypted) file.
``data``      ``<sequence number>.<encoded chunk>.<domain>``: the file.
``dilution``  ``<one vowel, repeated>.<domain>``: cover traffic, no data.

The size of a data chunk follows exactly from its length and the encoding, so
the net volume needs no estimate:

    base32     5 bits per character (no padding)
    base32map  5 bits per 3-letter word (each base32 character becomes a word)
    hex        4 bits per character
    base64     6 bits per character (older clients)

A retried query repeats the same sequence number and chunk; each chunk is
counted once (key: sequence number and chunk text). For every completed
transfer the unique chunks add up to the file size announced in the init.
"""
import base64
import binascii

from detection.detector_base.feature_extraction import get_fqdn, get_registered_domain, is_response

BITS_PER_CHAR = {"base32": 5.0, "base32map": 5.0 / 3.0, "hex": 4.0, "base64": 6.0}
# base32map alphabet of the client: base32 value -> word (dnsExfiltrator.cs, ``map``).
WORDS = ["kit", "van", "web", "you", "for", "set", "big", "fin", "sly", "app", "get", "hot", "mix", "dug",
         "ace", "arm", "era", "red", "led", "not", "hut", "car", "pen", "man", "she", "all", "sin", "leo",
         "sir", "run", "cut", "chi"]
_WORD_VALUE = {w: i for i, w in enumerate(WORDS)}
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
# Encoding numbers in the init (client ``EncodingToNumber``).
ENCODING_NUMBERS = {"0": "base32map", "1": "base32", "2": "hex"}


def chunk_bytes(chunk: str, encoding: str):
    """Bytes carried by one encoded chunk, or ``None`` for an unknown encoding."""
    encoding = str(encoding).lower()
    if encoding not in BITS_PER_CHAR:
        return None
    if encoding == "base32map":
        return (len(chunk) // 3) * 5 // 8
    return int(len(chunk) * BITS_PER_CHAR[encoding]) // 8


def decode_init(text: str):
    """Decode a complete init text to ``(encoding number, file size)``, else ``None``.

    The init is ``<encoding number>|<file size>|``; the trailing ``|`` marks it
    complete, so a prefix such as ``1|303`` of ``1|3030|`` is not mistaken for it.
    """
    if not text or len(text) % 3:
        return None
    try:
        b32 = "".join(_B32[_WORD_VALUE[text[i:i + 3]]] for i in range(0, len(text), 3))
        plain = base64.b32decode(b32 + "=" * (-len(b32) % 8)).decode("ascii")
    except (KeyError, binascii.Error, UnicodeDecodeError, ValueError):
        return None
    parts = plain.split("|")
    if len(parts) != 3 or parts[2] or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return parts[0], int(parts[1])


class DNSExfilPayload:
    """Classify the tunnel queries of one window and size their payload.

    Args:
        encoding: Encoding of the configuration (``dnsexfiltrator.*.encoding``).
    """

    def __init__(self, encoding: str):
        self.configured_encoding = self.encoding = str(encoding or "").lower()
        if self.encoding not in BITS_PER_CHAR:
            raise ValueError(f"unknown DNSExfiltrator encoding '{encoding}'")
        self._init_parts = []
        self.init = None  # (encoding number, file size) once the init was seen

    def classify(self, event: dict):
        """Return ``("data", key, bytes)``, ``("init", None, 0)``, ``("dilution", None, 0)`` or ``None``.

        ``None`` for responses and for queries outside the client's format.
        """
        if is_response(event):
            return None
        fqdn = (get_fqdn(event) or "").rstrip(".").lower()
        domain = get_registered_domain(event)
        if not fqdn or not domain or not fqdn.endswith("." + domain):
            return None
        labels = fqdn[: -len(domain) - 1].split(".")
        if len(labels) == 2 and labels[0].isdigit() and labels[1]:
            size = chunk_bytes(labels[1], self.encoding)
            return ("data", (labels[0], labels[1]), size) if size else None
        if len(labels) != 1 or not labels[0]:
            return None
        label = labels[0]
        if len(set(label)) == 1:
            return ("dilution", None, 0)
        self._add_init_part(label)
        return ("init", None, 0)

    def _add_init_part(self, label: str) -> None:
        # Init parts arrive in order; a retry starts over. Take the first run of
        # consecutive parts that decodes to "<number>|<size>".
        if self.init is not None:
            return
        self._init_parts.append(label)
        for start in range(len(self._init_parts)):
            decoded = decode_init("".join(self._init_parts[start:]))
            if decoded:
                self.init = decoded
                # The client announces what it actually uses; trust that over the
                # configuration (e.g. a client without base64 falls back to base32map).
                if self.announced_encoding in BITS_PER_CHAR:
                    self.encoding = self.announced_encoding
                return

    @property
    def announced_size(self):
        """File size announced in the init (the zipped, encrypted file), if seen."""
        return self.init[1] if self.init else None

    @property
    def announced_encoding(self):
        """Encoding announced in the init, if seen and known."""
        return ENCODING_NUMBERS.get(self.init[0], self.init[0]) if self.init else None
