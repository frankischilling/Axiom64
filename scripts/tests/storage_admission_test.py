#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check run ownership, actual runner admission and the read-only API protocol."""
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ci.storage_admission import GitHub, ObservationError, admitted, wait_for_admission

FIXTURE = json.loads((ROOT / 'scripts/tests/fixtures/storage-admission-da780.json').read_text())
SNAPSHOT = FIXTURE['snapshot']
RUN = SNAPSHOT['run']['id']
ATTEMPT = SNAPSHOT['run']['run_attempt']
HEAD = SNAPSHOT['run']['head_sha']


def running():
    snapshot = deepcopy(SNAPSHOT)
    snapshot['jobs'][0].update(status='in_progress', conclusion=None)
    return snapshot


def queued():
    snapshot = running()
    snapshot['jobs'][0].update(status='queued', runner_id=0, runner_name='')
    return snapshot


class Clock:
    def __init__(self):
        self.value = 0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


@contextmanager
def server(responses):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path, self.headers.get('Authorization')))
            code, body, extra = responses[self.path]
            self.send_response(code)
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *args):
            pass

    instance = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=instance.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(instance.server_port), requests
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join()


class Admission(unittest.TestCase):
    def test_recorded_terminal_job_releases_storage(self):
        result = admitted(SNAPSHOT, RUN, ATTEMPT, HEAD)
        self.assertEqual(result, dict(reason='network-terminal', job_id=SNAPSHOT['jobs'][0]['id'],
                                      network_conclusion='success'))

    def test_running_requires_assigned_runner_and_executed_step(self):
        snapshot = running()
        result = admitted(snapshot, RUN, ATTEMPT, HEAD)
        self.assertEqual(result['reason'], 'network-runner-started')
        self.assertEqual(result['first_step_started_at'], snapshot['jobs'][0]['steps'][0]['started_at'])
        for change in (dict(runner_id=0), dict(runner_id=True), dict(runner_name=False),
                       dict(runner_name=''), dict(steps=[]), dict(steps=None), dict(status='queued')):
            with self.subTest(change=change):
                value = deepcopy(snapshot)
                value['jobs'][0].update(change)
                self.assertIsNone(admitted(value, RUN, ATTEMPT, HEAD))

    def test_queue_timestamp_is_not_admission(self):
        value = queued()
        value['jobs'][0]['started_at'] = SNAPSHOT['jobs'][0]['steps'][0]['started_at']
        self.assertIsNone(admitted(value, RUN, ATTEMPT, HEAD))
        value = running()
        value['jobs'][0]['steps'][0].update(status='queued', started_at=None)
        self.assertIsNone(admitted(value, RUN, ATTEMPT, HEAD))

    def test_stale_or_ambiguous_job_inventory_rejects(self):
        mutations = [lambda s: s['run'].update(id=RUN + 1),
                     lambda s: s['run'].update(run_attempt=ATTEMPT + 1),
                     lambda s: s['run'].update(run_attempt=True),
                     lambda s: s['run'].update(head_sha='0' * 40),
                     lambda s: s['jobs'][0].update(run_id=RUN + 1),
                     lambda s: s['jobs'][0].update(head_sha='0' * 40),
                     lambda s: s['jobs'].append(deepcopy(s['jobs'][0])),
                     lambda s: s['jobs'].append(dict(s['jobs'][0], id=s['jobs'][0]['id'] + 1)),
                     lambda s: s['jobs'][0].update(status='unknown')]
        for index, change in enumerate(mutations):
            with self.subTest(index=index):
                value = running()
                change(value)
                with self.assertRaises(ObservationError):
                    admitted(value, RUN, ATTEMPT, HEAD)

    def test_malformed_executed_step_time_rejects(self):
        for timestamp in ('not-a-time', '2026-10-27T03:52:47', 17):
            with self.subTest(timestamp=timestamp):
                value = running()
                value['jobs'][0]['steps'][0]['started_at'] = timestamp
                with self.assertRaises(ObservationError):
                    admitted(value, RUN, ATTEMPT, HEAD)

    def test_failed_network_releases_unrelated_tests_without_claiming_success(self):
        value = deepcopy(SNAPSHOT)
        value['jobs'][0]['conclusion'] = 'failure'
        result = admitted(value, RUN, ATTEMPT, HEAD)
        self.assertEqual(result['reason'], 'network-terminal')
        self.assertEqual(result['network_conclusion'], 'failure')
        value['jobs'][0]['conclusion'] = None
        self.assertIsNone(admitted(value, RUN, ATTEMPT, HEAD))

    def test_bounded_polling_stops_at_actual_admission(self):
        clock = Clock()
        calls = []

        def fetch(deadline):
            calls.append(deadline)
            return queued() if len(calls) == 1 else running()

        report = wait_for_admission(fetch, RUN, ATTEMPT, HEAD, interval=2, clock=clock.now, sleep=clock.sleep)
        self.assertTrue(report['passed'])
        self.assertEqual(len(calls), 2)
        self.assertEqual(report['observation_seconds'], 2)

    def test_nullable_progress_waits_for_a_real_observation(self):
        clock = Clock()
        first = running()
        first['jobs'][0]['steps'] = None
        second = deepcopy(SNAPSHOT)
        second['jobs'][0]['conclusion'] = None
        values = [first, second, deepcopy(SNAPSHOT)]
        calls = []

        def fetch(deadline):
            calls.append(deadline)
            return values[len(calls) - 1]

        report = wait_for_admission(fetch, RUN, ATTEMPT, HEAD, interval=2,
                                    clock=clock.now, sleep=clock.sleep)
        self.assertTrue(report['passed'])
        self.assertEqual(len(calls), 3)
        self.assertEqual(report['observation_seconds'], 4)

    def test_timeout_never_treats_queued_job_as_started(self):
        clock = Clock()
        calls = []

        def fetch(deadline):
            calls.append(deadline)
            return queued()

        report = wait_for_admission(fetch, RUN, ATTEMPT, HEAD, seconds=5, interval=2,
                                    clock=clock.now, sleep=clock.sleep)
        self.assertFalse(report['passed'])
        self.assertEqual(len(calls), 3)
        self.assertEqual(report['observation_seconds'], 5)
        self.assertIn('not observed', report['error'])

    def test_missing_or_incomplete_target_cannot_release_storage(self):
        clock = Clock()
        value = deepcopy(SNAPSHOT)
        value['jobs'] = []
        report = wait_for_admission(lambda deadline: value, RUN, ATTEMPT, HEAD, seconds=1,
                                    clock=clock.now, sleep=clock.sleep)
        self.assertFalse(report['passed'])
        value = {'run': SNAPSHOT['run']}
        report = wait_for_admission(lambda deadline: value, RUN, ATTEMPT, HEAD)
        self.assertFalse(report['passed'])
        self.assertEqual(report['error'], 'incomplete admission observation')


class Protocol(unittest.TestCase):
    def test_attempt_pagination_and_authorized_get_requests(self):
        prefix = f'/repos/example/project/actions/runs/{RUN}'
        jobs = [dict(SNAPSHOT['jobs'][0], id=1000 + n, name='worker-' + str(n)) for n in range(100)]
        responses = {prefix: (200, SNAPSHOT['run'], {}),
                     prefix + f'/attempts/{ATTEMPT}/jobs?per_page=100&page=1':
                         (200, dict(total_count=101, jobs=jobs), {}),
                     prefix + f'/attempts/{ATTEMPT}/jobs?per_page=100&page=2':
                         (200, dict(total_count=101, jobs=SNAPSHOT['jobs']), {})}
        with server(responses) as (url, requests):
            api = GitHub('example/project', RUN, ATTEMPT, 'private-test-token', api=url)
            value = api.snapshot(time.monotonic() + 10)
            self.assertEqual(admitted(value, RUN, ATTEMPT, HEAD)['reason'], 'network-terminal')
            self.assertEqual(len(requests), 3)
            self.assertTrue(all(method == 'GET' and token == 'Bearer private-test-token'
                                for method, path, token in requests))
            self.assertNotIn('private-test-token', json.dumps(value))

    def test_subsequent_poll_reopens_the_same_job(self):
        prefix = f'/repos/example/project/actions/runs/{RUN}'
        job_id = SNAPSHOT['jobs'][0]['id']
        responses = {prefix: (200, SNAPSHOT['run'], {}),
                     prefix + f'/attempts/{ATTEMPT}/jobs?per_page=100&page=1':
                         (200, dict(total_count=1, jobs=queued()['jobs']), {}),
                     f'/repos/example/project/actions/jobs/{job_id}':
                         (200, running()['jobs'][0], {})}
        with server(responses) as (url, requests):
            api = GitHub('example/project', RUN, ATTEMPT, 'private-test-token', api=url)
            first = api.snapshot(time.monotonic() + 10)
            self.assertIsNone(admitted(first, RUN, ATTEMPT, HEAD))
            second = api.snapshot(time.monotonic() + 10)
            self.assertEqual(admitted(second, RUN, ATTEMPT, HEAD)['reason'], 'network-runner-started')
            self.assertEqual(second['inventory'], 'selected-network-job')
            self.assertEqual(len(requests), 4)
            self.assertEqual(sum('/attempts/' in path for method, path, token in requests), 1)

    def test_selected_job_endpoint_cannot_substitute_another_job(self):
        prefix = f'/repos/example/project/actions/runs/{RUN}'
        job_id = SNAPSHOT['jobs'][0]['id']
        wrong = dict(running()['jobs'][0], id=job_id + 1)
        responses = {prefix: (200, SNAPSHOT['run'], {}),
                     prefix + f'/attempts/{ATTEMPT}/jobs?per_page=100&page=1':
                         (200, dict(total_count=1, jobs=queued()['jobs']), {}),
                     f'/repos/example/project/actions/jobs/{job_id}': (200, wrong, {})}
        with server(responses) as (url, requests):
            api = GitHub('example/project', RUN, ATTEMPT, 'private-test-token', api=url)
            api.snapshot(time.monotonic() + 10)
            with self.assertRaisesRegex(ObservationError, 'selected network job identity'):
                api.snapshot(time.monotonic() + 10)

    def test_incomplete_second_page_rejects(self):
        prefix = f'/repos/example/project/actions/runs/{RUN}'
        jobs = [dict(SNAPSHOT['jobs'][0], id=1000 + n, name='worker-' + str(n)) for n in range(100)]
        responses = {prefix: (200, SNAPSHOT['run'], {}),
                     prefix + f'/attempts/{ATTEMPT}/jobs?per_page=100&page=1':
                         (200, dict(total_count=101, jobs=jobs), {}),
                     prefix + f'/attempts/{ATTEMPT}/jobs?per_page=100&page=2':
                         (200, dict(total_count=101, jobs=[]), {})}
        with server(responses) as (url, requests):
            api = GitHub('example/project', RUN, ATTEMPT, 'private-test-token', api=url)
            with self.assertRaisesRegex(ObservationError, 'complete paginated'):
                api.snapshot(time.monotonic() + 10)

    def test_http_error_body_and_token_stay_out_of_failure(self):
        prefix = f'/repos/example/project/actions/runs/{RUN}'
        with server({prefix: (403, {'error': 'private-test-token'}, {})}) as (url, requests):
            api = GitHub('example/project', RUN, ATTEMPT, 'private-test-token', api=url)
            report = wait_for_admission(api.snapshot, RUN, ATTEMPT, HEAD)
            self.assertFalse(report['passed'])
            self.assertEqual(report['error'], 'GitHub observation HTTP 403')
            self.assertNotIn('private-test-token', json.dumps(report))

    def test_redirect_does_not_forward_the_read_token(self):
        prefix = f'/repos/example/project/actions/runs/{RUN}'
        with server({prefix: (302, {}, {'Location': '/other-repository'})}) as (url, requests):
            api = GitHub('example/project', RUN, ATTEMPT, 'private-test-token', api=url)
            with self.assertRaisesRegex(ObservationError, 'HTTP 302'):
                api.snapshot(time.monotonic() + 10)
            self.assertEqual(len(requests), 1)


if __name__ == '__main__':
    unittest.main()
