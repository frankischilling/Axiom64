"""Expire one real interface-scoped ARP cache entry through GDB."""
import subprocess
from fetch import ROOT


def expire(index, port, prefix):
    source = "'kernel/net/ipv4/core.cpp'::'ax::(anonymous namespace)::neighbors'"
    address = 0x0a170101 + ((index - 1) << 8)
    script = ROOT / 'build' / f'{prefix}-cache-{index}.gdb'
    script.write_text('\n'.join([
        'set pagination off', 'set confirm off', f'file {ROOT / "build/axiom64.elf"}',
        f'target remote 127.0.0.1:{port}', 'set $i = 0', 'set $expired = 0',
        'while $i < 128', f'set $entry = &{source}[$i]',
        f'if $entry->index == {index} && $entry->address == {address} && '
        '(unsigned)$entry->state == 2 && $entry->expires > ax::ticks',
        f'printf "IPV4_CACHE_EXPIRED index={index} old=%llu now=%llu\\n", '
        '$entry->expires, ax::ticks',
        'set $entry->expires = ax::ticks', 'set $expired = $expired + 1', 'end',
        'set $i = $i + 1', 'end', 'if $expired != 1',
        'python raise RuntimeError("expected exactly one live reachable neighbor")',
        'end', 'detach', 'quit', '']))
    log = ROOT / 'build' / f'{prefix}-cache-{index}-gdb.log'
    with log.open('w') as output:
        process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(script)],
                                   stdout=output, stderr=subprocess.STDOUT)
    return process, log


def hold_arp_reply(index, port, prefix, armed, released):
    """Return EAGAIN at the real Ethernet transmit boundary until release."""
    # At the exact SysV x86-64 entry, no prologue has changed the stack.
    # The freestanding kernel has no unwind tables; forcing a return from an
    # optimized source-line breakpoint would misidentify its saved return PC.
    condition = (f'$rdi == {index} && $rdx == 60 && '
                 '((unsigned char*)$rsi)[12] == 8 && ((unsigned char*)$rsi)[13] == 6 && '
                 '((unsigned char*)$rsi)[20] == 0 && ((unsigned char*)$rsi)[21] == 2')
    script = ROOT / 'build' / f'{prefix}-arp-reply-{index}.gdb'
    script.write_text('\n'.join([
        'set pagination off', 'set confirm off', f'file {ROOT / "build/axiom64.elf"}',
        f'target remote 127.0.0.1:{port}', 'set $held = 0',
        f'break *ax::net_send if {condition}',
        'commands', 'silent',
        f'python gdb.set_convenience_variable("hold", int(not __import__("os").path.exists({str(released)!r})))',
        'if $hold', 'if !$held',
        f'printf "IPV4_ARP_REPLY_HELD index={index}\\n"', 'set $held = 1', 'end',
        'return (int)-11', 'continue', 'end',
        f'printf "IPV4_ARP_REPLY_RESUMED index={index}\\n"', 'detach', 'quit', 'end',
        f'python open({str(armed)!r}, "w").write("armed")', 'continue', '']))
    log = ROOT / 'build' / f'{prefix}-arp-reply-{index}-gdb.log'
    with log.open('w') as output:
        process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(script)],
                                   stdout=output, stderr=subprocess.STDOUT)
    return process, log
