#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Release storage matrices after this attempt's network job owns a runner."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[2]


class ObservationError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ObservationError(message)


def positive(value):
    return type(value) is int and value > 0


def admitted(snapshot, run_id, attempt, head):
    run = snapshot['run']
    require(positive(run['id']) and positive(run['run_attempt']) and
            run['id'] == run_id and run['run_attempt'] == attempt and run['head_sha'] == head,
            'current run, attempt and source head')
    jobs = snapshot['jobs']
    require(isinstance(jobs, list) and all(positive(j['id']) and positive(j['run_id']) and j['run_id'] == run_id and
            j['head_sha'] == head and isinstance(j['name'], str) and j['name'] for j in jobs),
            'jobs belong to the selected run and source')
    require(len({j['id'] for j in jobs}) == len(jobs) and
            len({j['name'] for j in jobs}) == len(jobs), 'unique job identities and names')
    selected = [j for j in jobs if j['name'] == 'Test network']
    if not selected:
        return None
    job = selected[0]
    if job['status'] == 'completed':
        if job.get('conclusion') is None:
            return None
        require(job['conclusion'] in ('success', 'failure', 'cancelled', 'timed_out',
                'action_required', 'neutral', 'skipped', 'stale', 'startup_failure'),
                'terminal network result is recorded')
        # A failed network job must not stop unrelated storage coverage. The
        # original qemu aggregate still requires the network matrix to succeed.
        return dict(reason='network-terminal', job_id=job['id'],
                    network_conclusion=job['conclusion'])
    require(job['status'] in ('queued', 'waiting', 'pending', 'requested', 'in_progress'),
            'known network job state')
    assigned = positive(job.get('runner_id')) and isinstance(job.get('runner_name'), str) and job['runner_name']
    if job['status'] != 'in_progress' or not assigned:
        return None
    steps = [s for s in (job.get('steps') or []) if s['status'] in ('in_progress', 'completed') and
             s.get('started_at') and s.get('conclusion') != 'skipped']
    if not steps:
        return None
    first = min(steps, key=lambda s: s['number'])
    require(positive(first['number']), 'executed step number')
    require(isinstance(first['started_at'], str) and isinstance(first['name'], str),
            'executed network step fields')
    try:
        started = datetime.fromisoformat(first['started_at'].replace('Z', '+00:00'))
    except (TypeError, ValueError) as error:
        raise ObservationError('executed network step timestamp') from error
    require(started.tzinfo is not None, 'executed network step has a timezone')
    # queued job.started_at can predate runner admission. Require an actual
    # executed step and assigned runner, rather than that queue timestamp.
    return dict(reason='network-runner-started', job_id=job['id'], runner_id=job['runner_id'],
                runner_name=job['runner_name'], first_step=first['name'],
                first_step_started_at=first['started_at'])


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class GitHub:
    def __init__(self, repository, run_id, attempt, token, api='https://api.github.com'):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'repository name')
        require(positive(run_id) and positive(attempt) and token, 'run identity and read token')
        self.actions = f'{api}/repos/{repository}/actions'
        self.base = f'{self.actions}/runs/{run_id}'
        self.attempt = attempt
        self.network_job_id = None
        self.opener = build_opener(NoRedirect())
        self.headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Axiom64-storage-admission'}

    def read(self, url, deadline):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'admission observation deadline')
        try:
            with self.opener.open(Request(url, headers=self.headers), timeout=min(10, remaining)) as response:
                return json.load(response)
        except HTTPError as error:
            # Do not retain response bodies or request headers: a failed server
            # or proxy must not put credentials in logs or uploaded evidence.
            raise ObservationError(f'GitHub observation HTTP {error.code}') from None
        except (URLError, TimeoutError, OSError):
            raise ObservationError('GitHub observation transport failed') from None
        except (UnicodeError, json.JSONDecodeError):
            raise ObservationError('GitHub observation JSON is invalid') from None

    def snapshot(self, deadline):
        run = self.read(self.base, deadline)
        if self.network_job_id is not None:
            job = self.read(f'{self.actions}/jobs/{self.network_job_id}', deadline)
            require(job['id'] == self.network_job_id, 'previously selected network job identity')
            return dict(run={name: run[name] for name in ('id', 'run_attempt', 'head_sha')},
                        jobs=[job], inventory='selected-network-job')
        endpoint = f'{self.base}/attempts/{self.attempt}/jobs?per_page=100&page='
        first = self.read(endpoint + '1', deadline)
        count = first['total_count']
        require(type(count) is int and 0 <= count <= 1000, 'bounded current attempt job inventory')
        jobs = first['jobs']
        require(isinstance(jobs, list), 'job inventory list')
        for page in range(2, (count + 99) // 100 + 1):
            following = self.read(endpoint + str(page), deadline)
            require(following['total_count'] == count, 'stable paginated job inventory')
            require(isinstance(following['jobs'], list), 'paginated job inventory list')
            jobs.extend(following['jobs'])
        require(len(jobs) == count, 'complete paginated job inventory')
        selected = [job for job in jobs if job.get('name') == 'Test network']
        if len(selected) == 1 and positive(selected[0].get('id')):
            self.network_job_id = selected[0]['id']
        # Other jobs are needed only to bind the complete initial inventory.
        # Later polls reopen the selected job, avoiding repeated large matrix
        # step inventories while retaining the run and attempt checks.
        fields = ('id', 'run_id', 'head_sha', 'name', 'status', 'conclusion', 'runner_id', 'runner_name')
        records = [{**{name: job.get(name) for name in fields},
                    'steps': job.get('steps', []) if job.get('name') == 'Test network' else []} for job in jobs]
        return dict(run={name: run[name] for name in ('id', 'run_attempt', 'head_sha')},
                    jobs=records, inventory='complete-current-attempt')


def wait_for_admission(fetch, run_id, attempt, head, seconds=3600, interval=15,
                       clock=time.monotonic, sleep=time.sleep):
    require(positive(run_id) and positive(attempt) and re.fullmatch(r'[0-9a-f]{40}', head),
            'current run, attempt and full source head')
    require(0 < seconds <= 3600 and 0 < interval <= 30, 'bounded admission observation')
    started = clock()
    deadline = started + seconds
    report = dict(passed=False, run=run_id, attempt=attempt, head=head, snapshots=[])
    try:
        while clock() < deadline:
            snapshot = fetch(deadline)
            report['snapshots'].append(snapshot)
            result = admitted(snapshot, run_id, attempt, head)
            if result:
                report.update(passed=True, admission=result)
                break
            remaining = deadline - clock()
            if remaining > 0:
                sleep(min(interval, remaining))
        if not report['passed']:
            raise ObservationError('network runner admission was not observed before the deadline')
    except (ObservationError, KeyError, TypeError) as error:
        report['error'] = str(error) if isinstance(error, ObservationError) else 'incomplete admission observation'
    report['observation_seconds'] = clock() - started
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/storage-admission.json')
    args = parser.parse_args()
    report = dict(passed=False)
    try:
        run_id = int(os.environ['GITHUB_RUN_ID'])
        attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
        head = os.environ['EXPECTED_HEAD']
        api = GitHub(os.environ['GITHUB_REPOSITORY'], run_id, attempt, os.environ['GITHUB_TOKEN'])
        report = wait_for_admission(api.snapshot, run_id, attempt, head)
    except (ObservationError, ValueError, KeyError):
        report['error'] = 'invalid admission environment'
    names = ['scripts/ci/storage_admission.py', 'scripts/tests/storage_admission_test.py',
             '.github/workflows/build.yml']
    report['source_sha256'] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({name: value for name, value in report.items() if name not in ('snapshots', 'source_sha256')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
