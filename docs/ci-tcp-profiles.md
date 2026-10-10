# Complete TCP profiles in parallel CI jobs

The CI matrix runs loss, receive ordering, zero-window persist, configured user timeout,
old-ACK rejection and [challenge ACK intervals](tcp-challenge-ack.md) in six isolated
jobs. Each receives the exact source/build artifact and retains three native libc
comparisons, eight VM firmware/transport/linkage cases, both adapters, real protocol
waits and independent positive/negative packet checks. Ordinary TCP sockets remain a
separate job. The earlier five profiles keep their established commands and records.

The profile matrix names are `tcp-fault-loss`, `tcp-fault-reordering`,
`tcp-fault-persist`, `tcp-fault-timeout`, `tcp-fault-old-ack` and
`tcp-fault-challenge`. Each publishes `axiom64-evidence-<suite>` and
`axiom64-<suite>-fixtures`, where `<suite>` is the complete matrix name. Download all
six pairs to audit complete TCP acceptance, including twelve static/dynamic images.
The build job publishes corresponding source, test inputs and compiled products.

All earlier non-profile suites remain present. `fail-fast: false` preserves evidence
from other jobs when one fails. The required `qemu` aggregate checks the build and
entire matrix: 39 successful jobs are required. Failed, cancelled, missing or skipped
profile acceptance blocks integration.

The accepted [five-profile serial run](https://github.com/frankischilling/Axiom64/actions/runs/38082099595)
and [parallel run](https://github.com/frankischilling/Axiom64/actions/runs/38083705139)
completed every required gate. TCP acceptance feedback after the shared build fell
from 1,836 to 566 seconds; whole-workflow elapsed time fell from 2,240 to 1,180 seconds.
The serial run also spent 1,305 seconds downloading inputs in its critical carrier
job, so the whole-workflow difference includes runner/setup and queue effects. The
protocol commands and real waits retained their full durations.

[#149](https://github.com/frankischilling/Axiom64/issues/149) is closed for that measured
redistribution. Wider manager/CI timing work remains in #133. TCG stays the default;
the complete manager matrix and VM-before-hardware requirements remain in force.
