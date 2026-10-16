# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind normal guest transfers to actual DHCP/DNS and complete HTTP/TLS streams."""
from collections import Counter
import hashlib
import re
import struct

from http_download.audit import fingerprint
from http_download.normal_dns_wire import verify as dns
from http_download.wire import PAYLOAD_BYTES, PAYLOAD_SHA256, stream
from random_crypto.wire import records, server_hello
from tcp_fault_capture import packets, require


def plain(group):
    request, reply = stream(group, True), stream(group, False)
    first = request.split(b'\r\n')[0]
    require(re.fullmatch(rb'GET /(fixed|small) HTTP/1\.[01]', first) and request.endswith(b'\r\n\r\n'),
            'actual normal HTTP request')
    header, body = reply.split(b'\r\n\r\n', 1)
    lines = header.split(b'\r\n')
    require(lines[0] == b'HTTP/1.1 200 OK', 'actual normal successful HTTP response')
    fields = {}
    for line in lines[1:]:
        name, value = line.split(b':',1)
        require(name.lower() not in fields, 'normal unique response fields')
        fields[name.lower()] = value.strip()
    require(fields.get(b'connection') == b'close' and b'transfer-encoding' not in fields and
            int(fields[b'content-length']) == len(body), 'normal complete fixed HTTP framing')
    if first.split()[1] == b'/fixed':
        require(len(body) == PAYLOAD_BYTES and hashlib.sha256(body).hexdigest() == PAYLOAD_SHA256,
                'independent normal complete HTTP binary bytes')
    else:
        require(body == b'Axiom64 output permission fixture\n', 'actual normal permission-control response')
    return dict(request=request.hex(), header=(header+b'\r\n\r\n').hex(), bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest())


def verify(directory, phases, network):
    require(not network['errors'] and network['host_resolver_unchanged'], 'actual normal DNS observer completed')
    results, actual_queries, actual_answers = [], Counter(), Counter()
    inventories = {str(lane): dict(http=[], tls=Counter(), large=Counter()) for lane in (0,1)}
    for phase in phases:
        for lane in (0,1):
            name = str(lane)
            peers = network['peers'][name]
            names = ('http','untrusted','fallback')
            ports = tuple(peers[role]['port'] for role in names)+(network['refused_ports'][name],)
            path = directory / phase['phase'] / f'lane{lane}.pcap'
            require(fingerprint(path) == phase['captures'][path.name], 'actual normal capture fingerprint')
            udp = dns(path, lane)
            actual_queries.update(udp['queries'])
            actual_answers.update(udp['answers'])
            groups = {}
            for row in packets(path,lane,ports):
                frame = row['frame']
                at = 14+(frame[14] & 15)*4
                source,target = struct.unpack_from('!HH',frame,at)
                guest = source if row['outgoing'] else target
                role = names[row['role']] if row['role'] < len(names) else 'refused'
                groups.setdefault((role,guest),[]).append(row)
            flows = []
            for (role,guest),group in groups.items():
                if role == 'refused':
                    require(not any(row['data'] for row in group) and
                            any(row['outgoing'] and row['flags'] & 2 for row in group) and
                            any(not row['outgoing'] and row['flags'] & 4 for row in group),
                            'actual refused endpoint has SYN and returned reset without application bytes')
                    flows.append(dict(role=role,guest_port=guest,passed=True))
                    continue
                if role == 'http':
                    value = plain(group)
                    inventories[name]['http'].append(value)
                    flows.append(dict(role=role,guest_port=guest,**value))
                    continue
                client,server = stream(group,True),stream(group,False)
                sent,received = records(client),records(server)
                require(sent and sent[0][0] == 22 and sent[0][1][0] == 1, 'normal actual TLS ClientHello')
                cipher,version = server_hello(received)
                require((cipher,version) == ((0xc02f,None) if role == 'fallback' else (0x1302,b'\x03\x04')),
                        'actual normal TLS 1.2 fallback or TLS 1.3 verified-helper negotiation')
                require(b'GET /fixed HTTP/1.1' not in client+server, 'normal TLS request is encrypted on the wire')
                inventories[name]['tls'][role] += 1
                large = len(server) > PAYLOAD_BYTES
                if large:
                    require(any(kind == 23 for kind,_ in sent) and any(kind == 23 for kind,_ in received),
                            'normal encrypted application records in both directions')
                    inventories[name]['large'][role] += 1
                flows.append(dict(role=role,guest_port=guest,cipher=cipher,
                    version=version.hex() if version else '0303',full_response_records=large,
                    client_sha256=hashlib.sha256(client).hexdigest(),server_sha256=hashlib.sha256(server).hexdigest()))
            require(sum(role == 'refused' for role,_ in groups) == len(phase['curl_profiles']),
                    'every selected normal client has an actual connection-refused control')
            results.append(dict(phase=phase['phase'],lane=lane,passed=True,capture=fingerprint(path),
                                DHCP=udp['leases'],tcp_flows=len(groups),flows=flows))
    require(actual_queries == Counter(row['query'] for row in network['queries']) and
            actual_answers == Counter(row['answer'] for row in network['queries']),
            'every actual normal guest DNS query and reply matches the separate native observer')
    for lane,inventory in inventories.items():
        peers = network['peers'][lane]
        require(Counter(row['request'] for row in inventory['http']) ==
                Counter(row['request'] for row in peers['http']['requests']), 'actual normal plain request inventory')
        for actual in inventory['http']:
            observed = [row for row in peers['http']['requests'] if row['request'] == actual['request']]
            require(observed and all(row['response_header'] == actual['header'] and
                    (row['body_bytes'],row['body_sha256']) == (actual['bytes'],actual['sha256']) for row in observed),
                    'normal actual captured response matches independently observed native bytes')
        for role in ('untrusted','fallback'):
            peer = peers[role]
            require(inventory['tls'][role] == len(peer['requests'])+len(peer['rejected_handshakes'])+
                    len(peer['rejected_after_handshake']) and inventory['large'][role] == len(peer['requests']),
                    'all normal TLS connections and full encrypted transfers match native observations')
    return dict(passed=True,captures=len(results),tcp_flows=sum(row['tcp_flows'] for row in results),
                actual_DHCP_DNS_and_HTTP_bytes=True,actual_TLS_records=True,tls_decrypted=False,
                DNS_queries=sum(actual_queries.values()),rows=results)
