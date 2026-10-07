#!/bin/bash
set -e
printf '\033[2J\033[HAxiom64\n\n'
printf 'Xorg framebuffer / twm / xterm / Bash %s\n\n' "$BASH_VERSION"
uname -a
printf '\nNative GNU tools and musl are available.\n'
printf 'Try: gcc --version, make -C /root/toolchain-test test, or zsh\n\n'
printf 'XTERM_BASH_PASS\n' > /tmp/xterm-ready
export PS1='axiom64:\w\$ '
exec /bin/bash --noprofile --norc -i
