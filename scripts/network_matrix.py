#!/usr/bin/env python3
"""Run the complete Ethernet matrix without rebuilding between matching boots."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import file_digest
import json
import os
from pathlib import Path
import random
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory
from fetch import ROOT
from network_test import fixture, run


def cases():
    for transport in ['modern', 'legacy']:
        for queue in [256, 512, 1024]:
            for firmware in ['bios', 'uefi']:
                yield dict(firmware=firmware, transport=transport, models=['virtio', 'e1000'], queue=queue)
        for firmware in ['bios', 'uefi']:
            common = dict(firmware=firmware, transport=transport, queue=512)
            yield dict(common, models=['virtio', 'e1000'] * 4)
            yield dict(common, models=['virtio', 'e1000'], wrap=True)
            yield dict(common, models=['virtio'], status=False)
            yield dict(common, models=['virtio', 'e1000'], mtu=9000)
            for fault in ['length', 'id']:
                yield dict(common, models=['virtio'], fault=fault)
            yield dict(common, models=['virtio'], pressure=True)
    for firmware in ['bios', 'uefi']:
        yield dict(firmware=firmware, transport='modern', models=['e1000'], queue=256, fault='length')
        yield dict(firmware=firmware, transport='modern', models=['virtio'], queue=256, mtu=1500)
        yield dict(firmware=firmware, transport='modern', models=['e1000'], queue=256, pressure=True)


def image_key(case):
    phase = 'verify'
    if case.get('pressure'):
        phase = 'pressure'
    elif case.get('fault'):
        phase = 'invalid' if case['fault'] == 'id' else 'error'
    elif case.get('wrap'):
        phase = 'queue'
    return case.get('status', True), phase


def prepare_images(matrix, directory):
    last = image_key(matrix[-1])
    keys = dict.fromkeys(map(image_key, matrix))
    images = {}
    previous_status = None
    # Publish the same final root archive and ISO as the serial matrix.
    for status, phase in sorted(keys, key=lambda key: (key[0] == last[0], key == last)):
        if previous_status != status:
            fixture(status)
            previous_status = status
        output = directory / f'{phase}-status{int(status)}'
        subprocess.run([sys.executable, str(ROOT / 'scripts/image.py'), '--test',
                        '--suite', 'network', '--phase', phase,
                        '--output-name', 'network-test.iso', '--output-directory', str(output)],
                       check=True)
        images[status, phase] = output / 'network-test.iso'
    publication = directory / 'network-test.iso'
    os.link(images[last], publication)
    os.replace(publication, ROOT / 'build/network-test.iso')
    return images


def run_case(case, image):
    options = dict(timeout=300 if case.get('wrap') else 45, wrap=False)
    options.update(case)
    with TemporaryDirectory(prefix='axiom64-net-') as directory:
        return run(**options, image_path=image, socket_directory=directory)


def run_matrix(workers, seed):
    matrix = list(cases())
    results = {}
    order = list(range(len(matrix)))
    random.Random(seed).shuffle(order)
    build = ROOT / 'build'
    build.mkdir(exist_ok=True)
    ledger = build / 'network-results.json'
    schedule = build / 'network-matrix-schedule.json'
    ledger.write_text('[]\n')
    schedule.unlink(missing_ok=True)
    with TemporaryDirectory(prefix='network-images-', dir=build) as directory:
        images = prepare_images(matrix, Path(directory))
        fingerprints = {}
        for key, image in images.items():
            with image.open('rb') as stream:
                fingerprints[key] = file_digest(stream, 'sha256').hexdigest()
        schedule.write_text(json.dumps(dict(seed=seed, workers=workers, order=order, cases=[
            dict(case, image_sha256=fingerprints[image_key(case)]) for case in matrix
        ]), indent=2) + '\n')
        pool = ThreadPoolExecutor(max_workers=workers)
        try:
            pending = {pool.submit(run_case, matrix[index], images[image_key(matrix[index])]): index for index in order}
            for job in as_completed(pending):
                results[pending[job]] = job.result()
                ledger.write_text(json.dumps([results[index] for index in sorted(results)], indent=2) + '\n')
        finally:
            pool.shutdown(cancel_futures=True)
    if len(results) != len(matrix) or not all(result['passed'] for result in results.values()):
        return 1
    print(f'NETWORK_MATRIX_PASS boots={len(results)} seed={seed} workers={workers}', flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workers', type=int, choices=(1, 2),
                        default=2 if len(os.sched_getaffinity(0)) >= 4 else 1)
    parser.add_argument('--seed', type=int, default=secrets.randbits(64))
    args = parser.parse_args()
    return run_matrix(args.workers, args.seed)


if __name__ == '__main__':
    raise SystemExit(main())
