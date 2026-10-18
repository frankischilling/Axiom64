# TCP output across permanent device loss

The device-loss fixture opens two real TCP streams on separate adapters. After
both complete a 16-byte exchange, it holds 512 bytes on the selected stream and
exchanges another 32 bytes on the original healthy stream. It then removes the
selected device. The failed socket must expose error readiness, its scoped read
and `SO_ERROR` results, EOF and `EPIPE`. The other original stream continues exact
request/reply exchanges for at least 5000 milliseconds and acknowledges both FINs.

```sh
mkdir -p build/tcp-device
sudo -n python3 scripts/tests/tcp_device_native_cleanup_test.py
sudo -n make test-tcp-device-native
make test-tcp-device
python3 scripts/tcp_device/capture.py
python3 scripts/tests/tcp_device_capture_test.py
```

The native comparison deletes an actual private Linux virtual netdevice while a
real netem queue retains its output. It configures `TCP_USER_TIMEOUT=3000` and
observes `ENETUNREACH` from the first read and `SO_ERROR`, then EOF and `EPIPE`.
Three libc linkages and both adapter selections require six observations. The
client, peer and caller occupy three separate network namespaces. No host network
settings change. Original kernel timestamps and independent monotonic packet
receipts remain available with zero-drop capture counters.
An additional failure probe starts the real C client, pauses it so its own
timeout cannot mask cleanup, and fails its peer. The fixture must stop its entire
owned process group. This probe remains separate from TCP timing acceptance.

The guest comparison physically removes an emulated PCI adapter with the default
TCP settings. Both selections run through all static/dynamic musl, BIOS/UEFI and
modern/legacy virtio combinations: sixteen observations. Each guest contains
virtio-net and e1000. Actual PCI port reads and QMP enumeration prove that only the
selected device disappears. The guest observes `EIO`, cleared `SO_ERROR`, EOF and
`EPIPE`. These hardware and deadline contracts differ from the scoped native
virtual-device comparison; identical errno behavior is not an acceptance claim.

An owned debugger holds the guest's real output boundary with `EAGAIN`. It records
the original frame and the identical pending IPv4 copy, its nonzero TCP owner and
zero transmitted-byte accounting. Actual device removal must produce `EIO` and
clear the copy's bytes, length and owner, leaving no remaining owned copy. The
healthy FIN must follow reclamation. Every guest retains the debugger's actual
successful exit status. Debugger timing does not establish retransmission policy.
The debugger observes the error at `inet_failed` entry with the saved TCP owner.
Before a later allocation can reuse the vacant slot, it records the saved copy's
cleared fields. It separately requires zero transmitted accounting and no
remaining copies for the old TCP owner. The healthy FIN must follow both checks.
This avoids depending on an optimized cleanup frame's return address or assuming
the slot stays vacant while other copies drain.

Four immutable boot images are prepared before at most two guests run
concurrently. Input manifests precede execution and bind the actual sources,
clients, runtime libraries, kernel, init and images. The auditor opens all four
ISOs and verifies their kernel, executables, loader and selected-adapter boot
arguments. It checks all 44 original captures, exact application streams,
acknowledged closes and full packet-clock and host-clock healthy intervals.

The negative controls alter copies of every profile's evidence. They cover
PCI identity and enumeration, forged device errors, pending ownership and
reclamation, held-frame bytes, observer status, native queue counters and device
inventory, syscall results, shortened intervals and original clock fingerprints.
They also reject a different error observation entry and mismatched TCP owner.
Both captures in every profile also receive checksum-repaired application-byte
corruption with corresponding peer and native receipt fingerprints rebound. Each
candidate must fail its intended semantic check. Changed files, rejection reasons
and hashes remain under `build/tcp-device/damaged/`; originals remain unchanged.

The quoted-ICMP CI job runs this complete cohort and publishes
`build/tcp-device/` with its evidence artifact and the four ISOs with its fixture
artifact. Existing protocol, deadline, carrier and recovery gates remain required.
