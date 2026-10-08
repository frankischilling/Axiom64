"""Corrupt one real QEMU RX completion at the driver's validation boundary."""
import subprocess
from fetch import ROOT


def inject(model, kind, port, prefix, armed):
    source = f'kernel/drivers/net/{model}.cpp'
    target = f"'{source}'::'ax::(anonymous namespace)::controllers'[0]"
    if model == 'virtio':
        location = 'kernel/drivers/virtio/queue.cpp'
        marker = 'const auto& entry = used_entries_['
        condition = '$nic->rx.used_ring_[1] != $nic->rx.consumed_'
        entry = '$nic->rx.used_entries_[$nic->rx.consumed_ & ($nic->rx.size_ - 1)]'
        mutation = f'set {entry}.id = $nic->rx.size_' if kind == 'id' else \
                   f'set {entry}.length = $nic->capacity + 1'
    else:
        location = source
        marker = 'bool end = descriptor.status & 2;'
        condition = '$nic->rx[$nic->rx_next].status & 1'
        mutation = 'set $nic->rx[$nic->rx_next].length = 1519'
    lines = (ROOT / location).read_text().splitlines()
    positions = [index + 1 for index, line in enumerate(lines) if marker in line]
    if len(positions) != 1:
        raise RuntimeError('the RX validation boundary is ambiguous or missing')
    script = ROOT / 'build' / (prefix + '.gdb')
    script.write_text('\n'.join([
        'set pagination off', 'set confirm off', f'file {ROOT / "build/axiom64.elf"}',
        f'target remote 127.0.0.1:{port}', f'set $nic = &{target}',
        f'break -source {location} -line {positions[0]} if {condition}',
        'commands', 'silent', mutation,
        f'printf "PACKET_FAULT_INJECTED model={model} kind={kind}\\n"',
        'detach', 'quit', 'end',
        f'python open({str(armed)!r}, "w").write("armed")', 'continue', '']))
    output = ROOT / 'build' / (prefix + '-gdb.log')
    with output.open('w') as stream:
        process = subprocess.Popen(['gdb', '-batch', '-x', str(script)],
                                   stdout=stream, stderr=subprocess.STDOUT)
    return process, output


def defer_tx(model, port, prefix, armed, released):
    """Defer completion observation without modifying device-written memory."""
    source = f'kernel/drivers/net/{model}.cpp'
    target = f"'{source}'::'ax::(anonymous namespace)::controllers'[0]"
    lines = (ROOT / source).read_text().splitlines()
    entries = [index + 2 for index, line in enumerate(lines)
               if line == 'static void poll(NetAdapter& adapter) {']
    sends = [index + 2 for index, line in enumerate(lines)
             if line == 'static int send(NetAdapter& adapter, const void* frame, size_t length) {']
    if len(entries) != 1 or len(sends) != 1:
        raise RuntimeError('the adapter polling or send boundary is ambiguous or missing')
    condition = '$nic->transmit[0].pending && $nic->transmit[0].length == 128' if model == 'virtio' else \
                '$nic->pending && $nic->tx[$nic->tx_oldest].length == 128'
    script = ROOT / 'build' / (prefix + '.gdb')
    script.write_text('\n'.join([
        'set pagination off', 'set confirm off', f'file {ROOT / "build/axiom64.elf"}',
        f'target remote 127.0.0.1:{port}', f'set $nic = &{target}', 'set $deferred = 0',
        f'break -source {source} -line {entries[0]} if {condition}',
        'commands', 'silent',
        f'python gdb.set_convenience_variable("hold", int(not __import__("os").path.exists({str(released)!r})))',
        'if $hold', 'if !$deferred',
        f'printf "PACKET_TX_DEFERRED model={model}\\n"', 'set $deferred = 1', 'end',
        'return', 'continue', 'end',
        f'printf "PACKET_TX_RELEASED model={model}\\n"', 'detach', 'quit', 'end',
        # Entry breakpoints can pause QEMU's virtual RX startup timer on every
        # idle poll. Enable deferral only after the ordinary handshake completes.
        'disable 1', f'break -source {source} -line {sends[0]} if length == 128',
        'commands', 'silent', 'enable 1', 'disable 2', 'continue', 'end',
        f'python open({str(armed)!r}, "w").write("armed")', 'continue', '']))
    output = ROOT / 'build' / (prefix + '-gdb.log')
    with output.open('w') as stream:
        process = subprocess.Popen(['gdb', '-batch', '-x', str(script)],
                                   stdout=stream, stderr=subprocess.STDOUT)
    return process, output
