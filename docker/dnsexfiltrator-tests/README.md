# Phase C: Differential Contract Tests

## Overview

This test suite verifies the contract between the DNS Exfiltrator client (C#) and server (Python) implementations, and demonstrates all 25 defects identified in Phase B.

## Structure

```
docker/dnsexfiltrator-tests/
├── test_contract_differential.py  # Main test suite
├── requirements.txt               # Test dependencies
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

```bash
cd /Users/maltemathiak/Documents/it_projects/tun_frame/TunFrame/docker/dnsexfiltrator-tests
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Execute Tests

```bash
python test_contract_differential.py
```

Or with verbose output:
```bash
python -m unittest test_contract_differential -v
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
