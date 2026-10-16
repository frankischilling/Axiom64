# Process resource limits

Each process owns a Linux resource-limit table. Threads share the table, fork copies it, and exec preserves it. The x86-64 `getrlimit`, `setrlimit` and `prlimit64` syscalls validate selectors, user memory, soft/hard ordering and permission to raise a hard limit. Remote `prlimit64` checks the target's real, effective and saved user/group IDs or the caller's resource capability. Aliased old/new buffers use a captured replacement value.

The current implementation enforces these resources:

| Resource | Behavior |
| --- | --- |
| `RLIMIT_NOFILE` | New descriptors must fit below the soft limit. Lowering it preserves existing high descriptors. Failed pipe pairs release their reserved slots. The current descriptor-table capacity also bounds the hard limit. |
| `RLIMIT_FSIZE` | Regular-file writes and growth through truncate respect the byte limit. Partial writes stop at the boundary; an operation starting there fails with `EFBIG` and `SIGXFSZ`. Vector operations validate the full length before accessing payload pages. Pipes, devices and zero-length writes retain their existing behavior. |
| `RLIMIT_NPROC` | Real-UID task counts include threads and unreaped process leaders. Linux root/capability exceptions apply. UID changes can defer quota denial until exec, which rechecks the current count. Exit and reaping release the appropriate counts. |
| `RLIMIT_AS` | Mappings, heap growth, shared-memory attachment and prepared executable images respect the process address-space allowance. Actual user mappings include `PROT_NONE` and shared pages. Fixed replacements validate admission before removing old pages. |
| `RLIMIT_DATA` | Private writable mappings and write upgrades consume the data allowance; shared and stack mappings are excluded. Fixed-map admission follows net virtual growth. A zero soft value permits the hard allowance for mappings, matching Linux's compatibility case. Heap changes instead check the byte allowance, including initial executable file data, even within an already mapped page. |
| `RLIMIT_STACK` | Anonymous grow-down mappings and the main stack can expand within the soft limit and address-space allowance. Existing pages survive a reduced limit. Permission failures, removed mappings and an accessible preceding mapping's guard gap prevent growth. The initial soft limit is 8 MiB and the hard limit is unlimited. |
| `RLIMIT_CPU` | User and kernel execution contribute to per-thread and process totals; idle scheduler time does not. `SIGXCPU` advances the visible soft limit once per CPU second, and the hard limit sends `SIGKILL`. Fork starts fresh counters; exec retains them. |

Process and thread CPU totals also back `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID`. The existing wall clock and 100 Hz elapsed-time interface remain separate.

Memory protection follows the x86 Linux distinction: `mmap` ignores bits outside the access permissions, while nonempty `mprotect` rejects unknown protection bits and accepts `PROT_SEM`. `PROT_GROWSDOWN` extends protection changes to the current stack mapping's lower boundary. Conflicting growth flags and unsupported grow-up mapping requests fail deliberately. Failed data/address-space admission preserves existing mapped contents. A denied prepared executable image leaves the caller's old image intact.

Exec captures a stack-limit snapshot with its owned argument/environment strings. Their combined byte/pointer budget is one quarter of the soft stack limit, with Linux's 128 KiB floor and 6 MiB ceiling. The actual initial stack layout must also fit the stack allowance. The loader reserves up to 128 KiB beyond the captured startup data and grows the stack through actual faults or kernel user-memory copies. Existing large-argument tests explicitly request an unlimited stack so they retain their full 6 MiB coverage.

The resource table recognizes all sixteen Linux selectors. Other stored values do not establish enforcement. Wider resource and service isolation remains unfinished; these limits alone do not establish readiness for exposed network services. Task slots, descriptor tables and other system-wide capacity bounds also remain.

## Validation

From the Linux build environment:

```sh
make test-process-limits-policy test-proc-identity-policy test-exec-arguments-policy
sudo python3 scripts/resource_limits_test.py --native --directory build/resource-limits-native
python3 scripts/resource_limits_test.py --directory build/resource-limits-guest
python3 scripts/resource_limits_storage_test.py --directory build/resource-limits-ext2
```

Use new output directories for each source revision. Native comparisons need root so their own children can exercise credential transitions and privileged exceptions. They run in isolated mount, PID and IPC namespaces.

The focused client checks real descriptor/file pressure, quota failures and reclamation, fork/thread/exec ownership, actual CPU use and signals, and mapping/protection/heap boundaries. Stack checks include 22 growth/protection/copy scenarios and twenty actual exec payload/limit combinations. Local validation passes six native libc/linkage profiles, eight BIOS/UEFI RAM guests and sixteen ext2 guests across both virtio transports: 300 observation groups. Independent inspection binds the executed source and binaries, actual ISO contents, sixteen fresh strict filesystem checks and persisted file bytes. All fourteen existing native/guest exec profiles also pass their nine groups. Hosted CI remains required for the proposed final revision.
