# DNSExfiltrator protocol tests (Phase C and E)

## Overview

This test suite verifies the contract between the DNS Exfiltrator client (C#) and server (Python) implementations, and demonstrates all 25 defects identified in Phase B. `test_phase_d_fixes.py` verifies the fixes applied in Phase D (see `PHASE_E_SUMMARY.md`).

Both suites are self-contained Python re-implementations of the client and server logic; they do not run `dnsExfiltrator.cs` or `dnsExfiltrator.py`. They model the protocol as it was during the review: the sequence number was a byte inside the encrypted chunk, and base64 was still an encoding. Since then the sequence number travels in its own label and base64 was removed from the tool; the current protocol is described in [documentation/dnsexfiltrator.md](../../documentation/dnsexfiltrator.md).

## Structure

```
docker/dnsexfiltrator-tests/
├── test_contract_differential.py  # Phase C: differential contract tests (22)
├── test_phase_d_fixes.py          # Phase E: verification of the Phase D fixes (5)
├── requirements.txt               # Test dependencies
├── PHASE_E_SUMMARY.md             # Results of the Phase E verification
└── README.md                      # This file
```

## Test Categories

### 1. B1: Config Parsing Tests
- Client option validation
- Server option validation
- `l=<size>` partially dead defect (CFG-001)
- No validation for numeric options

### 2. B2: Encoding & Label Construction Tests
- All encodings compatibility (base32, base32map, base64, hex)
- **B2-ENC-001 (Critical)**: chunkSize calculation missing -1 for sequence byte
- Label length enforcement

### 3. B3: Chunking/Sequencing/ACK/Reassembly Tests
- Sequencing compatibility (% 256)
- ACK protocol compatibility
- **B3-CHK-001 (Critical)**: No label length enforcement
- **B3-CHK-002 (High)**: No integrity check
- 7 exact abort paths in client

### 4. B4: Retry Handling Tests
- No distinction between failure types
- No exponential backoff
- **B4-RETRY-004 (High)**: Wrong ACK after server processed chunk

### 5. B5: Determinism & Server State Tests
- Deterministic data transfer
- Fresh process per config
- Race condition in pkill scenario

### 6. Differential Contract Tests
- INIT protocol contract
- Data chunk contract
- ACK contract
- All encodings compatibility

## Running the Tests

### Prerequisites

No extra packages are needed: the suites use only the Python standard library, so the project's virtual environment is enough.

```bash
cd docker/dnsexfiltrator-tests
```

### Execute Tests

```bash
python3 -m unittest test_contract_differential -v   # Phase C
python3 test_phase_d_fixes.py                        # Phase E
```

## Expected Output

The test suite should:
- Pass all encoding compatibility tests
- Demonstrate B2-ENC-001 by showing all encodings exceed DNS limits
- Demonstrate B3-CHK-001 (no label length enforcement)
- Demonstrate B3-CHK-002 (no integrity check)
- Demonstrate B4-RETRY-004 (wrong ACK scenario)

## Defects Demonstrated

| ID | Defect | Severity | Test Location |
|---|---|---|---|
| B2-ENC-001 | chunkSize calculation missing -1 for sequence byte | Critical | `test_B2_ENC_001_chunkSize_missing_sequence_byte` |
| B3-CHK-001 | No label length enforcement | Critical | `test_B3_CHK_001_no_label_length_enforcement` |
| B3-CHK-002 | No integrity check | High | `test_B3_CHK_002_no_integrity_check` |
| CFG-001 | labelMaxSize not enforced for data chunks | Medium | `test_l_option_partially_dead` |
| B4-RETRY-004 | Wrong ACK after server processed chunk | High | `test_B4_RETRY_004_wrong_ACK_after_server_processed_chunk` |

## Test Coverage

- **Total Defects from Phase B**: 25
- **Critical**: 2 (B2-ENC-001, B3-CHK-001)
- **High**: 5 (including B3-CHK-002, B4-RETRY-004)
- **Medium**: 12
- **Low**: 5
- **Info**: 2

## Notes

1. The test suite uses pure Python implementations to replicate both client and server behavior
2. RC4 implementation matches both client and server for accurate testing
3. All encoding/decoding logic matches the original implementations
4. Tests demonstrate defects by showing the conditions under which they occur

## Files Modified

- Created: `docker/dnsexfiltrator-tests/test_contract_differential.py`
- Created: `docker/dnsexfiltrator-tests/requirements.txt`
- Created: `docker/dnsexfiltrator-tests/README.md`

## Phase C Acceptance Criteria

- [x] Differential contract tests created
- [x] All Phase B defects demonstrated
- [x] Encoding compatibility verified
- [x] Chunking and sequencing contracts verified
- [x] Config parsing defects demonstrated
- [x] Retry handling defects demonstrated
- [x] Documentation provided
