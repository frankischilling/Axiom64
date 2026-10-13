"""Private fixture login and elevation through the installed normal console."""
import re
import shlex

from account_normal_test import PASSWORD, build_observer
from build_accounts import MODULES, digest
from fetch import ROOT


class ConsoleLogin:
    """Consume a cumulative serial capture; never place a password in a command."""

    def __init__(self, send):
        self.send = send
        self.cursor = 0
        self.stage = 'discover'
        self.ready = False
        self.length = 0
        self.events = []

    def consume(self, text):
        if isinstance(text, str):
            text = text.encode()
        if len(text) < self.length:
            raise RuntimeError('normal-login capture must be cumulative')
        self.length = len(text)
        if PASSWORD in text:
            raise RuntimeError('fixture password appeared in the serial capture')
        while True:
            remaining = text[self.cursor:]
            if b'Authentication failed.' in remaining:
                raise RuntimeError('normal fixture authentication was denied')
            if self.stage == 'discover':
                candidates = [(remaining.find(marker), marker, following, value)
                    for marker, following, value in (
                        (b'Administrator name: ', 'new', b'admin'),
                        (b'login: ', 'password', b'admin')) if marker in remaining]
                if not candidates:
                    return self.ready
                offset, marker, self.stage, value = min(candidates)
                self.cursor += offset + len(marker)
                self.send(value + b'\n')
                self.events.append('administrator' if self.stage == 'new' else 'login')
                continue
            prompts = {'new': (b'New password: ', 'confirm'),
                       'confirm': (b'Confirm password: ', 'created'),
                       'password': (b'Password: ', 'shell'),
                       'sudo': (b'Password: ', 'ready')}
            if self.stage in prompts:
                marker, following = prompts[self.stage]
                if marker not in remaining:
                    return self.ready
                self.cursor += remaining.index(marker) + len(marker)
                self.events.append(self.stage)
                self.send(PASSWORD + b'\n')
                self.stage = following
                continue
            if self.stage == 'created':
                marker = b'Administrator created. Please log in.'
                if marker not in remaining:
                    return False
                self.cursor += remaining.index(marker) + len(marker)
                self.stage = 'discover'
                continue
            if self.stage == 'shell':
                marker = re.search(rb'ACCOUNT_DESKTOP_READY uid=1000 server=\d+ clients=\d+\r?\n', remaining)
                if not marker or b'$ ' not in remaining[marker.end():]:
                    return False
                self.cursor += marker.end()
                self.stage, self.ready = 'ready', True
                self.events.append('ordinary-desktop')
                continue
            if self.stage == 'ready':
                if b'login: ' in remaining:
                    raise RuntimeError('the authenticated normal console session ended')
                return True
            raise RuntimeError('unknown fixture login stage')

    def elevate(self, command):
        if not self.ready or self.stage != 'ready':
            raise RuntimeError('elevation requires the authenticated ordinary session')
        if isinstance(command, bytes):
            command = command.decode()
        self.cursor = self.length
        self.stage = 'sudo'
        self.send(('sudo /bin/busybox sh -c ' + shlex.quote(command) + '\n').encode())


def install_observer(files, directory):
    """Keep installed init/account bytes; add the independently executed identity client."""
    program, inputs = build_observer(directory)
    files['usr/bin/account-normal-observe'] = (0o100755, program.read_bytes())
    names = [*(f'userspace/accounts/{name}.c' for name in MODULES),
             'userspace/accounts/logbook_rotation.c',
             *(str(path.relative_to(ROOT)) for path in (ROOT / 'userspace/accounts').glob('*.h')),
             'userspace/tests/security/account-normal-observe.c', 'scripts/build_accounts.py',
             'scripts/build_musl.py', 'scripts/build_libxcrypt.py', 'sources.lock.json']
    inputs['observer_source_sha256'] = {name: digest(ROOT / name) for name in names}
    return inputs
