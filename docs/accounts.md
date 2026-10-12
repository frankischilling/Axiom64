# Account records and authenticated identities

Account work is under development in [#115](https://github.com/frankischilling/Axiom64/issues/115), beneath [credentials #9](https://github.com/frankischilling/Axiom64/issues/9) and [sessions #25](https://github.com/frankischilling/Axiom64/issues/25). The current branch implements record storage, root administration, password decisions, credential installation, private interactive password entry and supervised ordinary shells. Normal-image first-boot/later-login integration, login/su/sudo commands, persistent login records and complete crash/fault acceptance remain unfinished.

## Records and transactions

`userspace/accounts/store.c` validates trusted directory ancestors, root ownership, exact file modes and single-link regular files. A process lock covers one complete immutable passwd/group/shadow generation. A successful update writes and synchronizes all three files before replacing the current pointer. Passwd and group use mode 0644; shadow and the lock use 0600. The current and preceding generations remain after successful cleanup. Missing current state with existing generations fails closed.

`database.c` owns the transaction and account/group relationships. `record.c` validates and serializes the seven-field passwd, four-field group and nine-field shadow layouts. Duplicate names or IDs, dangling primary groups or members, repeated shadow records, invalid numbers, malformed fields and inconsistent aging settings are rejected. Names use one to 32 lower-case ASCII letters, digits, underscores and hyphens, starting with a letter or underscore. IDs cover 0 through 4,294,967,294; root is the canonical UID/GID-zero account and group. Each serialized file is bounded to 1 MiB. Record counts and memberships use dynamic storage within that bound.

Renaming a user preserves numeric membership references; serialization emits the new name consistently. Changing a UID updates membership references. Changing a group ID updates primary-group references. A primary group cannot be deleted while a user depends on it. Invalid operations and failed allocation preserve the previous logical database. A commit reports whether publication happened when a later durability or cleanup operation fails, so callers cannot assume rollback after every error.

## Root administration

`accountctl` accepts an explicit command interface for bootstrap, user/group creation, deletion and rename, home/shell record changes, membership changes, password changes and locking. It requires real/effective UID zero and effective GID zero. `--database PATH` selects an isolated store for fixtures or root administration; the normal destination is `/etc/axiom64/accounts`.

Bootstrap creates a locked root account, the administrator's private primary group, and the `sudo` group. It hashes the administrator's password with maintained libxcrypt yescrypt, creates a private mode-0700 home owned by that administrator, and publishes the complete account set once. Later bootstrap attempts fail. Password values are read from a descriptor supplied by a protected pipe or provisioning source, never a command-line argument. The private interactive reader described below still needs integration with the guest login/provisioning frontend.

Examples, with descriptor 3 prepared privately by the provisioning caller:

```sh
accountctl bootstrap admin /home/admin /bin/bash --password-fd 3
accountctl group-add developers 1001
accountctl user-add alice 1001 developers /home/alice /bin/bash
accountctl member-add developers admin
accountctl password alice --password-fd 3
accountctl lock alice
accountctl unlock alice
accountctl show alice
```

New homes use trusted root-owned ancestors and reject existing final entries, including symlinks. Pre-publication rollback removes only the newly created empty home; it never recursively deletes its contents. Account deletion preserves home data. The command's status output reports whether a password is set or disabled without disclosing the hash. Full administrative session checks and conventional command aliases remain part of the unfinished account integration.

## Authentication and credential installation

`auth.c` validates the protected database and checks the maintained password verifier, aging fields and optional membership in `sudo` inside one locked snapshot. Wrong passwords, missing or locked accounts, account expiration, expired inactivity and disabled elevation deny access. Password aging follows the documented [shadow fields](https://man7.org/linux/man-pages/man5/shadow.5.html) and the boundary behavior checked against [Linux-PAM 1.7.1](https://github.com/linux-pam/linux-pam/blob/v1.7.1/modules/pam_unix/passverify.c). A forced or expired password change produces a profile that cannot install session credentials until reauthentication after the change. Returned profiles retain identity and group data without retaining the hash.

Installing a nonroot profile sets all real/effective/saved and filesystem UID/GID values, installs supplementary groups, clears retained capabilities, and verifies the resulting credentials. Service mode additionally sets no-new-privileges. Login environment construction replaces inherited variables with the identity's HOME, USER, LOGNAME and SHELL, a fixed PATH and locale, and an optional validated terminal type. A failed credential transition must terminate the child; it must never continue an application after a partial drop.

Real root administrators can select an existing locked service identity without a password. This operation is separate from password authentication. Ordinary session profiles permit later use of explicitly authorized set-ID tools; service profiles prevent privilege acquisition through exec.

## Private input and supervised terminals

`secret.c` reads a bounded password from the caller's foreground controlling terminal. It requires canonical input, disables both echo flags before displaying the prompt, drains invalid or overlong lines, and clears the complete output on failure. Success, EOF and cancellation restore the original terminal attributes and signal actions. SIGINT and SIGTERM take their original action after echo is restored. A caller must clear a successful password after verification or hashing.

PTY slaves start locked, with mode 0600 and the creator's filesystem UID/GID. Unlocking and relocking use the actual master lock; denied slave opens report EIO and invalidate existing slave I/O until a successful reopen, matching the [Linux 6.17 PTY implementation](https://github.com/torvalds/linux/blob/v6.17/drivers/tty/pty.c). Closing the final master unlinks the slave and hangs up its controlling session. Retained slave descriptors keep their own inode and ownership; an unrelated pair cannot reuse their identity. Unreferenced RAM device inodes are reclaimed. Terminal operations on unrelated character devices fail with ENOTTY. Session takeover requires the explicit privileged operation, and foreground/session queries enforce controlling-terminal membership.

`session.c` runs a command on a private PTY in a new session. Before exec, the child installs its complete profile, clears inherited environment, sets umask 077 and enters its home. A privileged begin callback runs after that setup and before the command is allowed to execute; failure prevents exec. The supervisor relays terminal input/output and resize events, reaps the child, closes the private master, restores the caller's terminal attributes and flags, and invokes the end callback. An ordinary caller's outer terminal ownership does not change. SIGTERM cleanup records the child's real exit status before restoring the original signal action. SIGKILL closes the sole private master through descriptor teardown; restoring an outer physical terminal and reconciling stale records after that forced failure belong to the remaining init/record integration.

The session fixture uses real protected files for begin/end callbacks. It does not establish the required utmp/wtmp/btmp policy or durable production logging. Complete job-control behavior and broader process/resource isolation also remain subject to their existing feature requirements.

## Runtime evidence and remaining work

Record tests pass in six native libc/linkage profiles and eight fresh BIOS/UEFI guest profiles, with 126 and 168 observations. They exercise renames, full-width IDs, relationship changes, real libc record parsers and twelve malformed committed databases. Administration tests pass across six native profiles and eight guests, with 138 command cases and 88 guest observations. Guest tests run actual `getpwnam_r`, `getgrnam_r`, `getspnam_r` and `initgroups`, including ordinary public lookup and shadow denial.

Authentication tests pass in six native profiles and eight guests, with 54 and 72 observations. They test password and aging denials, sudo membership, complete credential changes, cross-user file/process denial, environment/cwd/umask, and exec after a service privilege drop. The same set-UID executable first demonstrably grants effective/saved UID zero without no-new-privileges, then fails to acquire those privileges in service mode. Native set-ID controls use Linux filesystem fixtures, rather than relying on Windows-mount mode bits.

Private-terminal tests pass in six native profiles and eight BIOS/UEFI guests, with 54 and 80 observations. These cover creator ownership, an unrelated user's open/chmod denial, actual lock state and errors, controlling sessions, privileged and unprivileged takeover, last-master hangup, retained inode identity and 512 successive pairs without an inode leak per profile. Guest cases additionally check root-owned mode-0600 console, VT, raw input and framebuffer nodes, root access and fourteen ordinary-user open/chmod denials. Active graphical-seat access remains part of the normal-image integration; these raw devices are not granted to every user. The unchanged existing IPC client also passes separate BIOS/UEFI boots. Private password-entry tests pass across six native profiles and eight guests, with 54 and 72 observations; the actual master transcript contains no entered bytes, including invalid and overlong input.

The session matrix passes six native profiles and eight guests, with 60 and 80 observations. Each starts two authenticated BusyBox shells concurrently. Independent executed clients check all identity values, actual supplementary groups, private terminal ownership, foreground/session values, environment, working directory, capabilities, denied cross-user files/signals and private file creation. Failure coverage includes a rejected begin callback, actual exec failure, SIGTERM and SIGKILL supervisor termination, and caller-terminal disconnection. An independent byte comparison verifies all 40,960 output bytes across exit and backpressure. The native and guest helpers record source, compiler, maintained library, observer executable, actual BusyBox, image, log and process provenance. Native fixture contents and original ownership/mode/link metadata are exported before temporary directories can disappear.

The earlier store matrix retains eight RAM profiles, sixteen persistent ext2 cells, 32 fresh kernel boots and 32 independent filesystem checks. These store results establish persistence for the generation mechanism. Actual account administration/authentication across persistent reboots, concurrent command updates, real process/VM crashes, storage failures, production first-boot provisioning and later login, full elevation/administrative lifecycle, login records and complete current-head CI remain required before #115 can close. The normal-image startup has not yet switched to authenticated login. Wider glibc/NSS, remote sessions and isolation/resource-limit work remain in their parent issues.
