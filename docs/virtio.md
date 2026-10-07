# Virtio transport and split queues

`kernel/include/drivers/virtio/pci.hpp` handles polling PCI devices through modern MMIO or legacy I/O registers. `kernel/include/drivers/virtio/queue.hpp` owns split-ring storage, descriptor chains, completion identity, and CPU metadata. The block driver uses these modules for one outstanding request. Separate receive/transmit queues can hold several buffers in flight; Ethernet remains planned in [#51](https://github.com/frankischilling/Axiom64/issues/51).

## Driver lifecycle

Keep the transport, queues, and payload allocations alive throughout device ownership. These classes cannot be copied. Cleanup is explicit because a failed reset may require allocations to survive indefinitely.

1. `VirtioPci::open(pci, device_features, minimum_config_bytes)` discovers registers, resets, and negotiates features. Drivers select supported device bits 0 through 23; the module manages modern `VERSION_1`/`FEATURES_OK` and rejects unsupported transport features.
2. `setup_queue(queue, id, preferred_size, minimum_size)` configures each queue. Modern devices negotiate a power-of-two size no larger than the preference or offer, with readback checks. Legacy devices use their exact reported size. Up to eight queues can bind to one transport.
3. Allocate physically contiguous payloads and submit `VirtioBuffer { physical_address, length, writable }` arrays. Readable elements must precede writable elements. `queue.submit(buffers, count, cookie)` returns the chain head or a negative error. Exhaustion returns `-EAGAIN` without publishing a partial chain.
4. `start()` sets driver-ready status and notifies queues with pre-submitted buffers. After startup, use `notify(queue)` following a submission or batch.
5. `queue.complete(result)` returns one for a completion, zero when none is ready, or `-EIO` for a broken queue. The result contains the original cookie/head and device-reported used length. The driver validates its request-specific length, status, and payload. `wait(queue, result)` provides a bounded synchronous poll; asynchronous drivers must check `healthy()` and apply their own deadlines.
6. `stop()` resets the whole device. Only a successful return permits releasing outstanding payloads and calling `queue.release()`. On reset failure, retain every allocation and its ownership record. Later calls must not reuse or overwrite quarantined payloads.

`read_config(offset, output, length)` checks the advertised span and retries modern reads when the configuration generation changes. Register and queue operations require serialized callers. The block driver selects queue zero, a modern preference of 256, and a minimum of four descriptors.

## Ownership and ordering

`SplitQueue::create(size)` allocates a contiguous DMA ring and separate CPU metadata for power-of-two sizes 1 through 32768. `layout()` reports physical descriptor, available, and used addresses. Legacy used-ring alignment is preserved. An unbound queue has no device owner and may be released directly.

After address activation, `release()` refuses to free even an idle ring until reset succeeds. Barriers order descriptor publication, available indices, notifications, and completion reads. Completion counts must fit the outstanding heads; IDs must identify live chain heads. Out-of-order head completions work. Reclamation follows CPU-owned links, never a device-modified descriptor link. Queue indices use 16-bit rollover.

A malformed completion stops new submissions. The queue checks do not prove a device is trustworthy or impose a device-specific used-length contract. External payloads remain the driver's responsibility until valid completion or acknowledged reset; queue cleanup does not free them.

## Registers and limits

The module preserves assigned 32/64-bit BAR decoding, bounded capability walks, supervisor uncached mappings, register alignment, configuration generations, and notification bounds. MSI/MSI-X are disabled and INTx is masked. Available rings suppress used-buffer interrupts. Reset and synchronous polls use PIT-channel-2-calibrated TSC deadlines of two seconds plus a fixed iteration bound.

Callers currently run on one CPU. SMP synchronization, interrupt-driven completion, packed/indirect/event-index rings, individual queue reset, hotplug, PCIe ECAM, and IOMMU support remain planned. Offering an optional feature does not mean the guest negotiates it. Full scopes remain in [#1](https://github.com/frankischilling/Axiom64/issues/1), [#2](https://github.com/frankischilling/Axiom64/issues/2), and [#11](https://github.com/frankischilling/Axiom64/issues/11).

## Verification

```sh
make test-virtqueue
make test-virtio
make test-storage
make test-ext2
```

The sanitizer host test runs the production queue with a simulated device observing only the wire layout. It covers full queues, concurrent chains, out-of-order completion, descriptor reuse, corrupted IDs/counts/links, allocation failures, sizes up to 32768, and 70000 requests across index rollover. This verifies queue logic; actual guest tests cover register access and disk DMA.

The real-device matrix runs 24 boots across BIOS/UEFI, modern/legacy, and offered sizes 4, 128, and 1024. Each write boot checks both disks, unaligned/end-of-disk I/O, flushes, and 2052 reads across ring slots; a fresh boot recovers the written data. The host compares every disk byte after each boot. Variants change optional feature offers and device queue count. Modern size 1024 selects 256; legacy retains 1024. Evidence is `build/storage-*-q*.log` and `build/virtio-results.json`.

The existing 16-boot raw-disk matrix retains 65540-request rollover, read-only, reboot, and backend-error checks. The 68-boot ext2 matrix and full/thread/normal desktop suites remain required regressions. Reset refusal, malformed PCI capabilities, and malicious DMA completions are not fault-injected on real devices; sanitizer cases do not replace those future tests.

Register/ring contracts follow the [OASIS virtio 1.2 specification](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html). QEMU 8.2 limits these real block queues to 1024 ([device validation](https://github.com/qemu/qemu/blob/v8.2.2/hw/block/virtio-blk.c), [queue limit](https://github.com/qemu/qemu/blob/v8.2.2/include/hw/virtio/virtio.h)); larger layouts have host simulation coverage.
