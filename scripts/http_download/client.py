# SPDX-License-Identifier: GPL-3.0-or-later
"""Use the real command's exit status, diagnostics and downloaded file hashes."""
import re
import shlex

from http_download.peer import PAYLOAD_SHA256


def commands(curl, busybox, ca, untrusted, peers, host, output='.'):
    lines = ['set -eu', 'umask 077', 'cd ' + shlex.quote(str(output)),
        'curl() { ' + shlex.join(curl) + ' "$@"; }',
        'busybox() { ' + shlex.quote(str(busybox)) + ' "$@"; }',
        'test "$(busybox id -u)" = 60011', 'test "$(busybox id -g)" = 60011',
        'curl --version',
        '''run() {
    label="$1"; expected="$2"; shift 2
    if curl --noproxy '*' --http1.1 --connect-timeout 4 --max-time 15 --silent --show-error --fail --write-out "\\nDOWNLOAD_TIME $label %{time_total}\\n" "$@" > "$label.stdout" 2> "$label.stderr"; then
        actual=0
    else
        actual=$?
    fi
    printf 'DOWNLOAD_STATUS %s %s\\n' "$label" "$actual"
    busybox cat "$label.stdout"
    busybox cat "$label.stderr"
    test "$actual" = "$expected"
}''',
        '''hash() {
    value="$(busybox sha256sum "$1")"
    value="${value%% *}"
    printf 'DOWNLOAD_HASH %s %s\\n' "$1" "$value"
    test "$value" = "''' + PAYLOAD_SHA256 + '''"
}''']
    http = peers['http']
    resolve = ['--resolve', f'axiom64.test:{http.port}:{host}']
    url = f'http://axiom64.test:{http.port}'
    cases = {}

    def call(label, expected, args):
        cases[label] = expected
        lines.append('run ' + shlex.join([label, str(expected), *args]))

    for label, path, options in (('fixed', '/fixed', []), ('chunked', '/chunked', []),
                                 ('redirect', '/redirect', ['--location'])):
        call(label, 0, [*resolve, *options, '--output', label+'.bin', url+path])
        lines.append('hash '+label+'.bin')
    call('truncated', 18, [*resolve, '--output', 'resumed.bin', url+'/truncated'])
    lines.append('test "$(busybox wc -c < resumed.bin)" -gt 0')
    call('resume', 0, [*resolve, '--continue-at', '-', '--output', 'resumed.bin', url+'/range'])
    lines.append('hash resumed.bin')
    call('missing', 22, [*resolve, '--output', 'missing.bin', url+'/missing'])
    call('deadline', 28, [*resolve, '--max-time', '2', '--output', 'deadline.bin', url+'/stall'])
    call('permission', 23, [*resolve, '--output', 'deny/forbidden.bin', url+'/small'])
    for name in ('tls12', 'tls13', 'hostname', 'untrusted', 'expired', 'future'):
        peer = peers[name]
        hostname = 'wrong.test' if name == 'hostname' else 'axiom64.test'
        trusted = untrusted if name == 'untrusted' else ca
        options = ['--resolve', f'{hostname}:{peer.port}:{host}', '--cacert', str(trusted),
                   '--output', name+'.bin', f'https://{hostname}:{peer.port}/fixed']
        if name == 'tls12':
            options[0:0] = ['--tlsv1.2', '--tls-max', '1.2']
        call(name, 0 if name in ('tls12', 'tls13') else 60, options)
        if name in ('tls12', 'tls13'):
            lines.append('hash '+name+'.bin')
    lines.append('echo DOWNLOAD_CLIENT_PASS')
    return '\n'.join(lines)+'\n', cases


def verify(text, expected):
    rows = re.findall(r'^DOWNLOAD_STATUS ([a-z0-9-]+) ([0-9]+)\r?$', text, re.M)
    if len(rows) != len(expected) or {name: int(value) for name, value in rows} != expected:
        raise RuntimeError('actual download exit statuses differ')
    hashes = re.findall(r'^DOWNLOAD_HASH ([a-z0-9.-]+) ([0-9a-f]{64})\r?$', text, re.M)
    names = {'fixed.bin', 'chunked.bin', 'redirect.bin', 'resumed.bin', 'tls12.bin', 'tls13.bin'}
    if len(hashes) != len(names) or {name for name, _ in hashes} != names:
        raise RuntimeError('missing or repeated actual downloaded-file hash')
    if any(value != PAYLOAD_SHA256 for _, value in hashes):
        raise RuntimeError('guest-computed downloaded bytes differ')
    if len(re.findall(r'^DOWNLOAD_CLIENT_PASS\r?$', text, re.M)) != 1:
        raise RuntimeError('download client did not finish every case')
    times = re.findall(r'^DOWNLOAD_TIME ([a-z0-9-]+) ([0-9]+\.[0-9]+)\r?$', text, re.M)
    if len(times) != len(expected) or {name for name, _ in times} != set(expected):
        raise RuntimeError('actual client elapsed observations are incomplete')
    elapsed = {name: float(value) for name, value in times}
    if not 1.95 <= elapsed['deadline'] <= 5:
        raise RuntimeError('configured download deadline differs from real elapsed time')
    return dict(cases=len(rows), file_hashes=len(hashes), statuses=expected, elapsed_seconds=elapsed, passed=True)
