# Native IPv6 deprecation diagnosis

This temporary diagnostic observes a native Linux router-comparison failure.
It does not qualify Axiom64 behavior or replace the full build and boot workflow.

The C program includes the existing router client's actual assertion. It creates
four manually configured addresses and sends the exact zero-lifetime router
advertisement from the failed comparison. Up to 3,000 bounded diagnostic trials
stop at the first assertion failure. The one-second bound, expected flags and
protected address lifetimes remain unchanged. After a failure, a separate
read-only inventory records later flags for up to 125 seconds; that observation
cannot turn the original failure into a pass.

The Python driver compiles the native program, creates an isolated network
namespace and retains original packets, paired receipt clocks, serial records,
source hashes, compiler details and kernel identity. A private trace instance
records prefix processing and address-worker scheduling. The driver disables
and removes its probes and trace instance when collection ends. Trace buffer
statistics retain any overflow, so an incomplete trace stays visible.

Run as root on an expendable Linux diagnostic host:

```sh
sudo python3 -B scripts/diagnostics/ipv6_deprecation.py \
    --directory "$PWD/build/native-deprecation"
```

The single-job workflow runs only on `diagnostic/ipv6-deprecation-native` pushes.
It retains evidence for seven days. A green collection job means diagnostics
completed, including a reproduced failure. Check `namespace/receipt.json` and
the original serial log for the assertion result. Required feature validation
still needs the complete current-revision workflow and matching runtime evidence.


`--serialize-worker` tests a scheduling remedy on the same stock SMP kernel.
It pins the diagnostic process and unbound workers to the same available CPU
before creating the network namespace. This changes the expendable host's
global unbound-workqueue CPU mask for the diagnostic interval. The driver
records that mask and restores both original masks before returning. Use this
option only on a dedicated diagnostic host. Packets, clocks, lifetimes, expected
flags and the original assertion bounds stay unchanged. The workflow currently
selects this explicit experiment; it does not change required feature CI.
