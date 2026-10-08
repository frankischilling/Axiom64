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
