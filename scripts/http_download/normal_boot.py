# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive authenticated normal consoles without a guest test-init shortcut."""
import json
from collections import Counter
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import time

from account_normal_test import PASSWORD
from console_prompt import KERNEL_RECORD
from fetch import ROOT
from http_download.audit import fingerprint
from http_download.log import fault_free, healthy
from http_download.normal_client import PROFILES, files as download_files
from http_download.peer import PAYLOAD_SHA256
from normal_login import ConsoleLogin
from tcp_fault_capture import require


def view(data):
    # Preserve the raw serial capture; omit only complete, known kernel records
    # when recognizing a userspace marker split by asynchronous kernel output.
    return KERNEL_RECORD.sub(b'', data)


def marker(data, name):
    return re.search(rb'(?:^|\r)'+re.escape(name.encode())+rb'\r*$', view(data), re.M) is not None


def verify(data, fresh, persistent, firmware, profiles=PROFILES):
    health = healthy(data, firmware)
    observed = view(data)
    require(b'AXIOM64_EXIT status=0' in data and b'AXIOM64_TESTS_PASS' not in data and
            b'AXIOM64_TEST=1' not in data and PASSWORD not in data,
            'actual normal init and clean authenticated shutdown without a leaked credential')
    require(data.count(b'Administrator created. Please log in.') == int(fresh) and
            re.search(rb'ACCOUNT_DESKTOP_READY uid=1000 server=\d+', data),
            'actual administrator provisioning and ordinary desktop login')
    require(not persistent or b'VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0' in data,
            'actual writable ext2 root')
    identifiers = re.findall(rb'(?:^|\r)NORMAL_BOOT_ID ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\r*$',
                             observed, re.M)
    require(identifiers and len(set(identifiers)) == 1, 'one canonical actual kernel boot identity')
    if not fresh:
        require(marker(data, 'NORMAL_PERSISTED_BEFORE_NETWORK_PASS'), 'persisted files checked before new downloads')
        require(observed.index(b'NORMAL_PERSISTED_BEFORE_NETWORK_PASS') < observed.index(b'NORMAL_STATUS reboot'),
                'persisted-file checks precede every new reboot transfer result')
    statuses = re.findall(rb'(?:^|\r)NORMAL_STATUS ([a-z]+) ([a-z0-9-]+) ([0-9]+)\r*$', observed, re.M)
    expected = {}
    for provider in ('build', 'runtime'):
        for linkage in ('static', 'dynamic'):
            if provider+'-'+linkage not in profiles:
                continue
            for lane in (0, 1):
                label = f'{provider}-{linkage}-lane{lane}'
                if fresh:
                    expected[('public', label+'-public')] = 60
                    expected[('missing', label+'-store')] = 77
                    expected[('damaged', label+'-store')] = 77
                phase = 'trusted' if fresh else 'reboot'
                for name, code in (('http', 0), ('https', 0), ('nxdomain', 6), ('refused', 7),
                                   ('unreachable', 28), ('permission', 23)):
                    expected[(phase, label+'-'+name)] = code
    require(len(statuses) == len(expected) and
            {(phase.decode(), label.decode()): int(code) for phase,label,code in statuses} == expected,
            'all normal provider/linkage/adapter statuses match the actual command exits')
    times = re.findall(rb'(?:^|\r)NORMAL_TIME ([a-z]+) ([a-z0-9-]+) ([0-9]+\.[0-9]+)\r*$', observed, re.M)
    require(len(times) == len(expected) and {(phase.decode(), label.decode()) for phase,label,_ in times} == set(expected),
            'every actual curl command records its elapsed time')
    require(all(1.95 <= float(elapsed) <= 5 for _,label,elapsed in times if label.endswith(b'-unreachable')),
            'actual unreachable-neighbor deadline stays at two seconds')
    records = re.findall(rb'(?:^|\r)NORMAL_FILE (/home/admin/downloads/[a-z0-9-]+\.bin) ([0-9a-f]{64}) 600 1000 1000 1048593\r*$',
                         observed, re.M)
    repeats = {name: (1 if fresh or name.endswith('-fallback.bin') else 2) for name in download_files(profiles)}
    require(Counter(name.decode() for name,_ in records) == Counter(repeats) and
            all(value.decode() == PAYLOAD_SHA256 for _,value in records),
            'normal actual file hashes, private modes and ordinary ownership')
    wget = re.findall(rb'(?:^|\r)NORMAL_WGET_STATUS ([a-z]+) ([a-z0-9-]+) ([0-9]+)\r*$', observed, re.M)
    wget_expected = {}
    for lane in (0, 1):
        label = f'wget-lane{lane}'
        if fresh:
            for phase in ('public', 'missing', 'damaged'):
                wget_expected[(phase, label+'-store')] = 1
            wget_expected[('fallback', label+'-fallback')] = 0
        phase = 'trusted' if fresh else 'reboot'
        wget_expected.update({(phase, label+'-'+name): code for name,code in
                              (('http', 0), ('https', 0), ('wrong-name', 1))})
    require(len(wget) == len(wget_expected) and
            {(phase.decode(), label.decode()): int(code) for phase,label,code in wget} == wget_expected,
            'actual wget HTTP, verified helper and unverified fallback contract')
    return dict(passed=True, boot_id=identifiers[0].decode(), statuses=len(statuses),
                wget_statuses=len(wget), file_hashes=len(records), actual_ordinary_uid=1000, persistent=persistent,
                health=health)


def boot(directory, iso, network, firmware, transport, fresh, disk=None, timeout=180, profiles=PROFILES):
    directory.mkdir()
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '1G', '-nic', 'none',
               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane in (0, 1):
        model = ('virtio-net-pci,'+('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')) if lane == 0 else 'e1000'
        command += ['-netdev', f'user,id=net{lane},net=10.23.{lane+1}.0/24,host=10.23.{lane+1}.1,dns=10.23.{lane+1}.3,dhcpstart=10.23.{lane+1}.2',
                    '-device', model+f',netdev=net{lane},mac=52:54:00:65:00:0{lane}',
                    '-object', f'filter-dump,id=capture{lane},netdev=net{lane},file={directory / ("lane"+str(lane)+".pcap")}']
    firmware_inputs = {}
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file='+str(variables)]
        firmware_inputs = {name: fingerprint(Path('/usr/share/OVMF') / name)
                           for name in ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
    if disk is not None:
        command += ['-drive', 'if=none,format=raw,cache=writeback,file='+str(disk)+',id=root',
                    '-device', 'virtio-blk-pci,drive=root,'+
                    ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    command = network.command(command)
    actions = [
        (False, '/bin/busybox sh /usr/bin/normal-download-test public', 'NORMAL_PHASE_PASS public'),
        (True, '/bin/busybox mv /usr/bin/openssl /usr/bin/openssl-fixture-saved; echo NORMAL_HELPER_REMOVED', 'NORMAL_HELPER_REMOVED'),
        (False, '/bin/busybox sh /usr/bin/normal-download-test fallback', 'NORMAL_PHASE_PASS fallback'),
        (True, '/bin/busybox mv /usr/bin/openssl-fixture-saved /usr/bin/openssl; /bin/busybox cat /usr/share/download-fixture/ca.pem >> /etc/ssl/cert.pem; /bin/busybox sync; echo NORMAL_TRUST_INSTALLED', 'NORMAL_TRUST_INSTALLED'),
        (False, '/bin/busybox sh /usr/bin/normal-download-test trusted', 'NORMAL_PHASE_PASS trusted'),
        (True, '/bin/busybox mv /etc/ssl/cert.pem /etc/ssl/saved-trust.pem; echo NORMAL_TRUST_REMOVED', 'NORMAL_TRUST_REMOVED'),
        (False, '/bin/busybox sh /usr/bin/normal-download-test missing', 'NORMAL_PHASE_PASS missing'),
        (True, "printf 'damaged store\\n' > /etc/ssl/cert.pem; echo NORMAL_TRUST_DAMAGED", 'NORMAL_TRUST_DAMAGED'),
        (False, '/bin/busybox sh /usr/bin/normal-download-test damaged', 'NORMAL_PHASE_PASS damaged'),
        (True, '/bin/busybox cp /etc/ssl/saved-trust.pem /etc/ssl/cert.pem; /bin/busybox chmod 0644 /etc/ssl/cert.pem; /bin/busybox rm /etc/ssl/saved-trust.pem; /bin/busybox sync; echo NORMAL_TRUST_RESTORED', 'NORMAL_TRUST_RESTORED')
    ] if fresh else [(False, '/bin/busybox sh /usr/bin/normal-download-test reboot', 'NORMAL_PHASE_PASS reboot')]
    actions.append((True, '/bin/busybox sync; /bin/busybox poweroff -f', None))
    process, selector = None, selectors.DefaultSelector()
    data, phase, waiting, failure = bytearray(), 0, None, None
    started = time.monotonic()
    try:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        def send(value):
            process.stdin.write(value)
            process.stdin.flush()
        login = ConsoleLogin(send)
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic()+timeout
        with (directory / 'guest.log').open('wb') as log:
            while time.monotonic() < deadline:
                for key,_ in selector.select(.05):
                    chunk = os.read(key.fd, 65536)
                    if chunk:
                        data.extend(chunk)
                        log.write(chunk)
                        log.flush()
                login.consume(bytes(data))
                complete = bytes(data[:data.rfind(b'\n')+1])
                fault_free(complete)
                if login.ready and login.stage == 'ready' and phase < len(actions):
                    if waiting is None or marker(data, waiting):
                        elevated, text, waiting = actions[phase]
                        (login.elevate if elevated else login.command)(text)
                        phase += 1
                if process.poll() is not None:
                    break
            else:
                raise TimeoutError('normal download deadline phase='+str(phase)+' waiting='+str(waiting))
        require(process.wait(timeout=5) == 1 and phase == len(actions), 'complete actual normal-session process')
        result = verify(bytes(data), fresh, disk is not None, firmware, profiles)
        result.update(command=command, elapsed_seconds=time.monotonic()-started, deadline_seconds=timeout,
                      firmware_inputs=firmware_inputs, login_events=login.events,
                      curl_profiles=list(profiles),
                      log=fingerprint(directory / 'guest.log'),
                      captures={f'lane{lane}.pcap': fingerprint(directory / f'lane{lane}.pcap') for lane in (0,1)})
        (directory / 'receipt.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            process.stdin.close()
            process.stdout.close()
        (directory / 'process.json').write_text(json.dumps(dict(command=command,
            returncode=process.returncode if process else None, phase=phase, error=failure,
            elapsed_seconds=time.monotonic()-started, deadline_seconds=timeout), indent=2)+'\n')
