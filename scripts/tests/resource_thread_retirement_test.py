#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the actual resource client with native joiners and workers on separate CPUs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from http_download.native_process import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/resource-limits-thread-retirement')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('the actual native quota comparison needs the root build session')
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 2 or cpus[1] >= 1024:
        parser.error('the native retirement race needs two CPUs in the allowed affinity set')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'userspace/tests/process/resource-limits.c'
    inputs = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in (source, Path(__file__).resolve())}
    # Change scheduling at the real pthread call site; keep processes() and
    # its quota, zombie, join, fork and thread assertions exactly as written.
    program_source = '''#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
static int pinned_create(pthread_t* thread, const pthread_attr_t* attributes,
                         void* (*function)(void*), void* argument) {
    int result = pthread_create(thread, attributes, function, argument);
    if (!result) {
        cpu_set_t cpus;
        CPU_ZERO(&cpus);
        CPU_SET(WORKER_CPU, &cpus);
        int affinity = pthread_setaffinity_np(*thread, sizeof(cpus), &cpus);
        if (affinity) {
            fprintf(stderr, "THREAD_RETIREMENT_AFFINITY_FAIL error=%d\\n", affinity);
            exit(1);
        }
    }
    return result;
}
#define pthread_create pinned_create
#define main original_resource_main
#include RESOURCE_SOURCE
#undef main
#undef pthread_create
int main(void) {
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(JOINER_CPU, &cpus);
    CHECK(sched_setaffinity(0, sizeof(cpus), &cpus) == 0);
    for (unsigned iteration = 0; iteration < 10000; iteration++)
        isolated(processes, "native_thread_quota_reclamation");
    puts("RESOURCE_THREAD_RETIREMENT_PASS iterations=10000 separate_cpus=2");
    return 0;
}
'''
    generated = directory / 'comparison.c'
    generated.write_text(program_source)
    executable = directory / 'comparison'
    command = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               '-static', '-DWORKER_CPU=' + str(cpus[1]), '-DJOINER_CPU=' + str(cpus[0]),
               '-DRESOURCE_SOURCE=' + json.dumps(str(source)), str(generated), '-o', str(executable)]
    with (directory / 'build.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    process = run([str(executable)], directory / 'actual.log', None, 60)
    text = (directory / 'actual.log').read_text()
    count = text.splitlines().count('RESOURCE_LIMIT_OBSERVATION native_thread_quota_reclamation')
    passed = (process['returncode'] == 0 and not process['timed_out'] and count == 10000 and
              text.splitlines().count('RESOURCE_THREAD_RETIREMENT_PASS iterations=10000 separate_cpus=2') == 1 and
              'RESOURCE_LIMIT_FAIL' not in text)
    assert inputs == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    receipt = dict(passed=passed, iterations=count, joiner_cpu=cpus[0], worker_cpu=cpus[1],
                   source_inputs=inputs, command=command, process=process,
                   actual_binary_sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
    (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not passed:
        raise RuntimeError('actual joined-thread quota reclamation failed; retained ' + str(directory))
    print('RESOURCE_THREAD_RETIREMENT_PASS iterations=10000 separate_cpus=2')


if __name__ == '__main__':
    main()
