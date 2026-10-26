# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep the full surviving-stream observation after a delayed first send."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_device.capture import observation
from tcp_fault_peer import check

DELAY = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

static uint64_t now(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value))
        abort();
    return (uint64_t)value.tv_sec * 1000000000 + (uint64_t)value.tv_nsec;
}

ssize_t __real_send(int fd, const void* buffer, size_t size, int flags);

ssize_t __wrap_send(int fd, const void* buffer, size_t size, int flags) {
    static int delayed;
    if (!delayed && size == 64) {
        delayed = 1;
        struct timespec remaining = {0, 750000000};
        uint64_t began = now();
        while (nanosleep(&remaining, &remaining)) {
            if (errno != EINTR)
                abort();
        }
        printf("TCP_DEVICE_TEST_DELAY elapsed_ns=%llu\n",
               (unsigned long long)(now() - began));
    }
    return __real_send(fd, buffer, size, flags);
}
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-directory', type=Path,
                        default=ROOT / 'build/tcp-device/observation-regression')
    args = parser.parse_args()
    check(os.geteuid() == 0, 'actual private netdevice observations require root')
    output = args.output_directory.resolve()
    check(output.is_relative_to((ROOT / 'build').resolve()),
          'owned device observation outputs stay under build')
    output.mkdir(parents=True, exist_ok=False)
    parent_namespace = os.readlink('/proc/self/ns/net')
    record = dict(passed=False, injected_first_send_delay_ns=750000000,
                  original_packet_observation_us=5000000, guest_or_host_clock_changed=False)
    try:
        with tempfile.TemporaryDirectory(prefix='axiom64-device-observation-') as temporary:
            directory = Path(temporary)
            exported = directory / 'source'
            exported.mkdir()
            for name in ('scripts', 'kernel', 'userspace', 'vendor', 'boot', 'docs'):
                shutil.copytree(ROOT / name, exported / name,
                                ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            for name in ('Makefile', 'dependencies.json', 'sources.lock.json', 'ports.lock.json',
                         '.gitattributes', '.gitignore', '.clang-format', 'LICENSE', 'README.md'):
                shutil.copyfile(ROOT / name, exported / name)
            (exported / 'build').mkdir()
            client, wrapper = output / 'client.c', output / 'delay.c'
            shutil.copyfile(exported / 'userspace/tests/net/tcp_device.c', client)
            wrapper.write_text(DELAY)
            binary = exported / 'build/tcp-device-native'
            compile_command = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                               str(client), str(wrapper), '-Wl,--wrap=send', '-o', str(binary)]
            with (output / 'compile.log').open('wb') as log:
                subprocess.run(compile_command, check=True, stdout=log, stderr=subprocess.STDOUT)
            shutil.copyfile(binary, output / 'program')
            save(output / 'compile.json', dict(command=compile_command,
                client_sha256=digest(client), wrapper_sha256=digest(wrapper),
                program_sha256=digest(binary), test_source_sha256=digest(Path(__file__))))
            scratch = directory / 'namespace'
            scratch.mkdir()
            (scratch / 'parent-netns').write_text(parent_namespace)
            observed = output / 'linux-native-1'
            observed.mkdir()
            command = ['unshare', '--net', sys.executable,
                       str(exported / 'scripts/tcp_device/run.py'), '--namespace',
                       str(scratch), 'native', '1', str(observed)]
            with (output / 'namespace.log').open('wb') as log:
                completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                           timeout=60)
            row = json.loads((observed / 'producer-result.json').read_text())
            check(completed.returncode == 0 and row['passed'],
                  'actual delayed-send client, device deletion and live companion complete')
            actual_inputs = json.loads((observed / 'inputs.json').read_text())
            retained = output / 'runtime-inputs'
            for group in ('sources', 'products'):
                for name, expected in actual_inputs[group].items():
                    source = exported / name
                    check(digest(source) == expected, 'actual delayed-send source/product bytes')
                    target = retained / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists():
                        shutil.copyfile(source, target)
            text = (observed / 'client.log').read_text()
            delays = re.findall(r'^TCP_DEVICE_TEST_DELAY elapsed_ns=(\d+)$', text, re.M)
            check(len(delays) == 1 and int(delays[0]) >= 750000000,
                  'one actual delay precedes the first surviving progress send')
            record.update(actual_delay_ns=int(delays[0]),
                          original_client_source_sha256=digest(client),
                          actual_program_sha256=digest(output / 'program'),
                          producer_result_sha256=digest(observed / 'producer-result.json'))
            # This is the unchanged public packet/application/physical-operation verifier.
            result = observation(observed, row)
            check(result['passed'], 'full original surviving-stream observation remains visible')
            record.update(passed=True, observation=result)
    except BaseException as error:
        record.update(error_type=type(error).__name__, error=str(error))
        raise
    finally:
        record['original_namespace_preserved'] = os.readlink('/proc/self/ns/net') == parent_namespace
        save(output / 'result.json', record)
        check(record['original_namespace_preserved'], 'observation preserves the parent namespace')
    print('TCP_DEVICE_OBSERVATION_PASS first_send_delay_ms=750 packet_window_ms=5000')


if __name__ == '__main__':
    main()

