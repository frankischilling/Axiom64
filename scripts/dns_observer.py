# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind complete DNS driver observations to original physical Ethernet captures."""
from collections import Counter
import re
from dns_peer import check
from tcp_capture_link import ethernet_records, fnv


def link_receipts(text, path, lane, linkage):
    rows = re.findall(r'^DNS_LINK_FRAME linkage=(static|dynamic) index=(\d+) length=(\d+) '
                      r'hash=([0-9a-f]{16}) packet_type=(\d+) ether_type=([0-9a-f]{4}) '
                      r'monotonic_ms=(\d+)\r?$', text, re.M)
    check(len(rows) == text.count('DNS_LINK_FRAME ') and
          all(int(index) in (1, 2) and 14 <= int(length) <= 2048 and int(kind) in range(5) and
              ether_type != '0800' for _, index, length, _, kind, ether_type, _ in rows),
          'complete non-IPv4 DNS driver records')
    selected = [row for row in rows if row[:2] == (linkage, str(lane + 1))]
    claimed = Counter((int(length), digest, int(kind), ether_type)
                      for _, _, length, digest, kind, ether_type, _ in selected)
    available = Counter()
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    for row in ethernet_records(path):
        frame = row['frame']
        if frame[12:14] != b'\x08\x00':
            kind = (4 if frame[6:12] == guest else 0 if frame[:6] == guest else
                    1 if frame[:6] == b'\xff' * 6 else 2 if frame[0] & 1 else 3)
            available[(len(frame), fnv(frame), kind, frame[12:14].hex())] += 1
    check(not claimed - available, 'every DNS link receipt owns an original physical frame')
    clocks = [int(row[-1]) for row in selected]
    check(clocks == sorted(clocks), 'actual driver receipt clocks are monotonic')
    return len(selected)


def audit(peers, text, paths, linkages):
    receipts = re.findall(r'^DNS_FRAME linkage=(static|dynamic) index=(\d+) length=(\d+) '
                          r'hash=([0-9a-f]{16}) packet_type=(\d+) monotonic_ms=(\d+)\r?$', text, re.M)
    actual = Counter((int(index), int(length), digest, int(kind))
                     for _, index, length, digest, kind, _ in receipts)
    check(len(receipts) == text.count('DNS_FRAME '), 'complete IPv4 DNS driver records')
    links = re.findall(r'^DNS_LINK_FRAME linkage=(static|dynamic) index=(\d+) length=(\d+) '
                       r'hash=([0-9a-f]{16}) packet_type=(\d+) ether_type=([0-9a-f]{4}) '
                       r'monotonic_ms=(\d+)\r?$', text, re.M)
    check(len(links) == text.count('DNS_LINK_FRAME ') and
          all(int(index) in (1, 2) and 14 <= int(length) <= 2048 and int(kind) in range(5) and
              ether_type != '0800' for _, index, length, _, kind, ether_type, _ in links),
          'complete non-IPv4 DNS driver records')
    for lane in range(2):
        claimed = Counter((int(length), digest, int(kind), ether_type)
                          for _, index, length, digest, kind, ether_type, _ in links
                          if int(index) == lane + 1)
        available = Counter()
        guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        for row in ethernet_records(paths[lane]):
            frame = row['frame']
            if frame[12:14] == b'\x08\x00':
                continue
            kind = (4 if frame[6:12] == guest else 0 if frame[:6] == guest else
                    1 if frame[:6] == b'\xff' * 6 else 2 if frame[0] & 1 else 3)
            available[(len(frame), fnv(frame), kind, frame[12:14].hex())] += 1
        # Boot traffic may precede observer setup. Every claimed link receipt
        # still has to own an unchanged original physical Ethernet frame.
        check(not claimed - available, 'every DNS link receipt owns an original physical frame')
    expected = Counter()
    for peer in peers:
        for row in peer.frames:
            frame = bytes.fromhex(row['frame'])
            if frame[12:14] != b'\x08\x00':
                continue
            value = 0xcbf29ce484222325
            for byte in frame:
                value = (value ^ byte) * 0x100000001b3 & 0xffffffffffffffff
            expected[(peer.lane + 1, len(frame), f'{value:016x}', 4 if row['direction'] == 'query' else 0)] += 1
    physical = Counter()
    for lane in range(2):
        guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        subnet = bytes([10, 23, lane + 1])
        for row in ethernet_records(paths[lane]):
            frame = row['frame']
            if frame[12:14] == b'\x08\x00' and len(frame) >= 34 and (
                    frame[26:29] == subnet or frame[30:33] == subnet):
                kind = 4 if frame[6:12] == guest else 0
                physical[(lane + 1, len(frame), fnv(frame), kind)] += 1
    check(physical == expected, 'every DNS IPv4 observation owns an original physical frame')
    check(actual == expected and bool(actual), 'exact actual driver receipts match every host DNS query/reply frame')
    captures = re.findall(r'^DNS_CAPTURE_PASS linkage=(static|dynamic) index=(\d+) '
                          r'packets=(\d+) dropped=(\d+)\r?$', text, re.M)
    check(len(captures) == text.count('DNS_CAPTURE_PASS ') == 2 * len(linkages) and
          {(linkage, int(index)) for linkage, index, _, _ in captures} ==
          {(linkage, index) for linkage in linkages for index in (1, 2)},
          'both actual capture sockets in both linkages')
    for linkage, index, count, dropped in captures:
        rows = [row for row in receipts if row[:2] == (linkage, index)]
        link_rows = [row for row in links if row[:2] == (linkage, index)]
        check(int(dropped) == 0 and int(count) == len(rows) + len(link_rows),
              'complete capture with no dropped observer frames')
        for family in (rows, link_rows):
            clocks = [int(row[-1]) for row in family]
            check(clocks == sorted(clocks), 'actual driver receipt clocks are monotonic')
    return len(receipts) + len(links)
