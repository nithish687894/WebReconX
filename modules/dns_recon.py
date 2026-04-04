"""
DNS Reconnaissance — custom raw DNS query builder and parser.
No external DNS libraries required.
"""
import socket
import struct
import random
from typing import Any, Dict, List, Optional
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_info, print_warning


DNS_SERVER  = "8.8.8.8"
DNS_PORT    = 53
QUERY_TYPES = {
    "A":     1,
    "AAAA":  28,
    "MX":    15,
    "NS":    2,
    "TXT":   16,
    "CNAME": 5,
    "SOA":   6,
}


def _build_query(domain: str, qtype: int) -> bytes:
    """Build a raw DNS query packet."""
    txid   = random.randint(0, 0xFFFF)
    flags  = 0x0100          # standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)

    # Encode QNAME
    qname = b""
    for part in domain.split("."):
        encoded = part.encode()
        qname  += bytes([len(encoded)]) + encoded
    qname += b"\x00"

    question = qname + struct.pack(">HH", qtype, 1)   # QTYPE, QCLASS IN
    return header + question


def _parse_name(data: bytes, offset: int) -> tuple:
    """Parse a DNS name (handles compression pointers)."""
    labels, jumped = [], False
    original_offset = offset

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:          # pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = ptr
            jumped = True
        else:
            offset += 1
            labels.append(data[offset: offset + length].decode(errors="ignore"))
            offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def _query(domain: str, qtype_name: str, timeout: float = 5.0) -> List[str]:
    qtype  = QUERY_TYPES.get(qtype_name, 1)
    packet = _build_query(domain, qtype)
    answers: List[str] = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (DNS_SERVER, DNS_PORT))
        response, _ = sock.recvfrom(4096)
        sock.close()
    except Exception:
        return []

    # Parse header
    if len(response) < 12:
        return []
    ancount = struct.unpack(">H", response[6:8])[0]
    if ancount == 0:
        return []

    # Skip question section
    offset = 12
    while offset < len(response) and response[offset] != 0:
        if (response[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += response[offset] + 1
    else:
        offset += 1
    offset += 4   # QTYPE + QCLASS

    # Parse answer records
    for _ in range(ancount):
        if offset >= len(response):
            break
        _, offset = _parse_name(response, offset)
        if offset + 10 > len(response):
            break
        rtype, _, _, rdlength = struct.unpack(">HHIH", response[offset: offset + 10])
        offset += 10
        rdata = response[offset: offset + rdlength]
        offset += rdlength

        if rtype == 1 and len(rdata) == 4:           # A
            answers.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and len(rdata) == 16:        # AAAA
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype in (2, 5, 15):                     # NS, CNAME, MX
            name, _ = _parse_name(response, offset - rdlength + (2 if rtype == 15 else 0))
            answers.append(name)
        elif rtype == 16:                             # TXT
            txt = ""
            pos = 0
            while pos < len(rdata):
                seg_len = rdata[pos]; pos += 1
                txt += rdata[pos: pos + seg_len].decode(errors="ignore")
                pos += seg_len
            answers.append(f'"{txt}"')
        elif rtype == 6:                              # SOA
            mname, end = _parse_name(response, offset - rdlength)
            rname, _   = _parse_name(response, end)
            answers.append(f"mname={mname} rname={rname}")

    return answers


class DNSRecon(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        records: Dict[str, List[str]] = {}
        for qtype in QUERY_TYPES:
            results = _query(self.domain, qtype, timeout=self.timeout)
            if results:
                records[qtype] = results
        return {"domain": self.domain, "records": records}

    def display(self, results: Dict[str, Any]) -> None:
        records = results.get("records", {})
        if not records:
            print_warning("No DNS records found")
            return
        for qtype, values in records.items():
            for val in values:
                print_result(f"{qtype:<8} {val}")
        print_info(f"{sum(len(v) for v in records.values())} records across {len(records)} types")
