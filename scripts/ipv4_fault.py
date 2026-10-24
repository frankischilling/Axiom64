"""Control real ARP cache entries and NIC backpressure through GDB."""
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
    """Hold one NIC's TX until the guest acknowledges all RX recycling."""
    # At the exact SysV x86-64 entry, no prologue has changed the stack.
    # The freestanding kernel has no unwind tables; forcing a return from an
    # optimized source-line breakpoint would misidentify its saved return PC.
    # Repeated entry breakpoints also consume the real one-second queue
    # lifetime. Replace this NIC driver's entry once with mov eax,-11; ret,
    # then restore its exact bytes. Polling, RX and guest clocks keep running.
    condition = (f'$rdi == {index} && $rdx == 60 && '
                 '((unsigned char*)$rsi)[12] == 8 && ((unsigned char*)$rsi)[13] == 6 && '
                 '((unsigned char*)$rsi)[20] == 0 && ((unsigned char*)$rsi)[21] == 2')
    body = f'''import gdb, os, threading, time
mask = (1 << 64) - 1
source = "'kernel/net/ipv4/core.cpp'::'ax::(anonymous namespace)::output'"
released = {str(released)!r}
patch = bytes.fromhex('b8f5ffffffc3')
original = address = position = pointer = expires = None
def interrupt_when_released():
    while not os.path.exists(released):
        time.sleep(0.001)
    gdb.post_event(lambda: gdb.execute('interrupt'))
def install():
    global original, address, position, pointer, expires
    pointer = int(gdb.parse_and_eval('$rsi')) & mask
    for slot in range(32):
        entry = gdb.parse_and_eval(source + '[' + str(slot) + ']')
        if (int(entry['bytes']) & mask) == pointer:
            position, expires = slot, int(entry['expires'])
            break
    if position is None or os.path.exists(released):
        raise RuntimeError('expected an unreleased queued ARP reply')
    address = int(gdb.parse_and_eval("'kernel/net/ethernet.cpp'::'ax::devices'[{index - 1}]->send")) & mask
    inferior = gdb.selected_inferior()
    original = bytes(inferior.read_memory(address, len(patch)))
    if original == patch:
        raise RuntimeError('driver already has the EAGAIN patch')
    try:
        inferior.write_memory(address, patch)
        if bytes(inferior.read_memory(address, len(patch))) != patch:
            raise RuntimeError('EAGAIN patch did not read back')
    except BaseException:
        inferior.write_memory(address, original)
        raise
    bp.delete()
    print('IPV4_ARP_REPLY_HELD index={index} ticks=' + str(int(gdb.parse_and_eval('ax::ticks'))) +
          ' expires=' + str(expires) + ' address=' + hex(address) + ' original=' + original.hex())
    with gdb.blocked_signals():
        threading.Thread(target=interrupt_when_released, daemon=True).start()
def restore():
    inferior = gdb.selected_inferior()
    pc = int(gdb.parse_and_eval('$pc')) & mask
    patched = bytes(inferior.read_memory(address, len(patch)))
    inferior.write_memory(address, original)
    if bytes(inferior.read_memory(address, len(patch))) != original:
        raise RuntimeError('driver code restoration did not read back')
    # The stub changes only eax. If interrupted inside it, restart the
    # restored entry with its original arguments and untouched return stack.
    if address <= pc < address + len(patch):
        gdb.execute('set $pc = ' + str(address))
    now = int(gdb.parse_and_eval('ax::ticks'))
    entry = gdb.parse_and_eval(source + '[' + str(position) + ']')
    if patched != patch or not os.path.exists(released):
        raise RuntimeError('unexpected stop during NIC backpressure')
    if now >= expires or (int(entry['bytes']) & mask) != pointer:
        raise RuntimeError('queued ARP reply expired before release')
    print('IPV4_ARP_REPLY_RESUMED index={index} ticks=' + str(now) +
          ' expires=' + str(expires) + ' restored=' + original.hex())
bp = gdb.Breakpoint('*ax::net_send')
bp.condition = {condition!r}
open({str(armed)!r}, 'w').write('armed')'''
    script = ROOT / 'build' / f'{prefix}-arp-reply-{index}.gdb'
    script.write_text('\n'.join([
        'set pagination off', 'set confirm off', f'file {ROOT / "build/axiom64.elf"}',
        f'target remote 127.0.0.1:{port}', 'python', body, 'end',
        'continue', 'python install()', 'continue', 'python restore()', 'detach', 'quit', '']))
    log = ROOT / 'build' / f'{prefix}-arp-reply-{index}-gdb.log'
    with log.open('w') as output:
        process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(script)],
                                   stdout=output, stderr=subprocess.STDOUT)
    return process, log
