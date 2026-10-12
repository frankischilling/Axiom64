# Account records and authenticated identities

Account work is under development in [#115](https://github.com/frankischilling/Axiom64/issues/115), beneath [credentials #9](https://github.com/frankischilling/Axiom64/issues/9) and [sessions #25](https://github.com/frankischilling/Axiom64/issues/25). The current branch implements record storage, root administration, password decisions and credential installation. Normal-image login, terminal/session ownership, login records, logout supervision and complete crash/fault acceptance remain unfinished.

## Records and transactions

`userspace/accounts/store.c` validates trusted directory ancestors, root ownership, exact file modes and single-link regular files. A process lock covers one complete immutable passwd/group/shadow generation. A successful update writes and synchronizes all three files before replacing the current pointer. Passwd and group use mode 0644; shadow and the lock use 0600. The current and preceding generations remain after successful cleanup. Missing current state with existing generations fails closed.

`database.c` owns the transaction and account/group relationships. `record.c` validates and serializes the seven-field passwd, four-field group and nine-field shadow layouts. Duplicate names or IDs, dangling primary groups or members, repeated shadow records, invalid numbers, malformed fields and inconsistent aging settings are rejected. Names use one to 32 lower-case ASCII letters, digits, underscores and hyphens, starting with a letter or underscore. IDs cover 0 through 4,294,967,294; root is the canonical UID/GID-zero account and group. Each serialized file is bounded to 1 MiB. Record counts and memberships use dynamic storage within that bound.

Renaming a user preserves numeric membership references; serialization emits the new name consistently. Changing a UID updates membership references. Changing a group ID updates primary-group references. A primary group cannot be deleted while a user depends on it. Invalid operations and failed allocation preserve the previous logical database. A commit reports whether publication happened when a later durability or cleanup operation fails, so callers cannot assume rollback after every error.

## Root administration

`accountctl` accepts an explicit command interface for bootstrap, user/group creation, deletion and rename, home/shell record changes, membership changes, password changes and locking. It requires real/effective UID zero and effective GID zero. `--database PATH` selects an isolated store for fixtures or root administration; the normal destination is `/etc/axiom64/accounts`.

Bootstrap creates a locked root account, the administrator's private primary group, and the `sudo` group. It hashes the administrator's password with maintained libxcrypt yescrypt, creates a private mode-0700 home owned by that administrator, and publishes the complete account set once. Later bootstrap attempts fail. Password values are read from a descriptor supplied by a protected pipe or provisioning source, never a command-line argument. Interactive password entry still needs the guest login/provisioning frontend.

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

## Runtime evidence and remaining work

Record tests pass in six native libc/linkage profiles and eight fresh BIOS/UEFI guest profiles, with 126 and 168 observations. They exercise renames, full-width IDs, relationship changes, real libc record parsers and twelve malformed committed databases. Administration tests pass across six native profiles and eight guests, with 138 command cases and 88 guest observations. Guest tests run actual `getpwnam_r`, `getgrnam_r`, `getspnam_r` and `initgroups`, including ordinary public lookup and shadow denial.

Authentication tests pass in six native profiles and eight guests, with 54 and 72 observations. They test password and aging denials, sudo membership, complete credential changes, cross-user file/process denial, environment/cwd/umask, and exec after a service privilege drop. The same set-UID executable first demonstrably grants effective/saved UID zero without no-new-privileges, then fails to acquire those privileges in service mode. Native set-ID controls use Linux filesystem fixtures, rather than relying on Windows-mount mode bits.

The earlier store matrix retains eight RAM profiles, sixteen persistent ext2 cells, 32 fresh kernel boots and 32 independent filesystem checks. These store results establish persistence for the generation mechanism. Actual account administration/authentication across persistent reboots, concurrent command updates, real process/VM crashes, storage failures, production first-boot provisioning and later login, terminal ownership, login records, safe logout/failure cleanup and complete current-head CI remain required before #115 can close. Wider glibc/NSS, remote sessions and isolation/resource-limit work remain in their parent issues.
