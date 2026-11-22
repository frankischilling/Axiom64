# PXE boot and remote testing

PXE boots a test build over Ethernet. Use a direct cable from the build PC to
the test machine, or connect both to an isolated switch. The addresses below
are for a direct link with one Razer Blade. Use a subnet that does not overlap
with the build PC's other adapters.

## Build the PXE tree

Run these commands on Ubuntu or in WSL Ubuntu from the repository root.

```sh
make -j2 build/axiom64.elf build/rootfs-desktop.cpio
python3 scripts/boot_media.py pxe build/axiom64-pxe \
    --initramfs build/rootfs-desktop.cpio
```

Set the TFTP base directory to `build/axiom64-pxe`. Keep the tree intact so
Limine can find `limine.conf`, `boot/axiom64.elf`, and `boot/rootfs.cpio.gz`.
The output path must be new. Give each new build a new directory and switch the
TFTP base directory when the build is ready.

## Configure the wired link

On a Windows build PC, set the physical Ethernet adapter to
`192.168.100.3/24` with the gateway field empty. Run the DHCP and TFTP services
on Windows if the cable is connected to Windows and the build runs in WSL.
For example, in Tftpd64 select `192.168.100.3` as the server interface, set
the current directory to the PXE tree, and bind both services to that adapter.
Allow the server through the firewall on the test link.

| Setting | Value |
| --- | --- |
| Client address | `192.168.100.200`, one DHCP lease |
| Subnet mask | `255.255.255.0` |
| TFTP server | `192.168.100.3`, UDP port 69 with `tsize` support |
| DHCP TFTP server name (option 66) | `192.168.100.3` |
| DHCP boot file (option 67) | `BOOTX64.EFI` for x86-64 UEFI |
| Legacy BIOS boot file | `limine-bios-pxe.bin` |

Use one DHCP server per test link. On a managed network, ask its administrator
to add the boot options to the existing DHCP setup.

## Boot the Blade

1. Restart the Blade and press **F12** for its boot menu. Choose **IPv4 PXE**
   on the wired adapter. If the option is missing, enable the UEFI network
   stack and IPv4 network boot in firmware setup.
2. Check the station address. It should be `192.168.100.200` with the lease
   above. Confirm that the TFTP log shows `BOOTX64.EFI`, then the kernel and
   initramfs under `boot/`.
3. Check the guest screen or console for userspace startup. The firmware's
   DHCP lease proves the boot link is up. The guest configures its own
   interface after firmware hands off to the kernel.

If the station address appears and no file loads, check the boot filename,
the TFTP root, and the firewall on the physical interface. If all files load
and the screen goes blank, capture the last screen and the server log. The
failure can be after the network transfer, during kernel or display startup.

The stock PXE tree above runs entirely from RAM. Changes to the RAM root
disappear on reboot. See
[persistent root boot](disk-root.md) for building a separate system disk.

### Boot the NVMe installer

Build the installed profile first. Use its pinned Python and SSH runtime to
make a maintenance PXE tree for the direct Ethernet link.

```sh
make -j2 build/axiom64.elf build/rootfs-installed-desktop.cpio
python3 scripts/nvme_install_pxe.py build/axiom64-install-pxe \
    --authorized-key "$HOME/.ssh/axiom64-bench.pub" \
    --address 192.168.100.200/24 --client 192.168.100.3
```

Add `--usb-keyboard` for a boot-protocol USB keyboard connected directly to
the xHCI controller.

Point TFTP to the maintenance tree and choose **IPv4 PXE**. The guest generates
its host key on this boot and displays the fingerprint on the firmware
framebuffer and serial console. Check
the fingerprint before connecting from the build host with the matching key.
Upload the [NVMe bundle](disk-root.md#transfer-a-built-image-to-nvme) into the
`bench` home directory with SFTP. At the local maintenance console run
`python3 /installer.py inspect /dev/nvme0n1`. Preview the install using the
bundle in `/home/bench`, then follow the write instructions after verifying
the drive identity and backup.

### Try a new kernel with the installed system

After the installed disk boots on its own, record the GPT ID of its ext2 root
partition. The `VFS_ROOT_PASS` line on the serial console shows it after
`PARTUUID=`. Build a PXE tree for that root using the ID from the installed disk.

```sh
make -j2 build/axiom64.elf
python3 scripts/boot_media.py pxe build/axiom64-pxe-installed \
    --root-partuuid "$root_partuuid"
```

Set the TFTP base to the new tree and choose **IPv4 PXE**. Limine downloads the
kernel and a small bootstrap archive. Axiom64 mounts the selected NVMe root and
uses its installed accounts and programs. A local-disk boot still uses the kernel
stored on the EFI partition.

## SSH and SFTP

SSH requires a lab initramfs with OpenSSH. Stage the lab archive with
`scripts/boot_media.py pxe <new-directory> --initramfs <lab.cpio>`. Configure
the guest's wired address as `192.168.100.200/24`. Start `sshd` on that address
on TCP port 22 with a non-root account named `bench`, public-key authentication,
and the `internal-sftp` subsystem. Disable password login. Generate the host
key in the guest and read its fingerprint from a trusted console. Keep private
keys and credentials out of the TFTP tree. [OpenSSH host-key checking](https://man.openbsd.org/ssh_config.5)

Run the client on the build PC. Adjust `bench` and the key path to match the
lab image. On the first connection, compare the displayed fingerprint with
the one from the guest console before accepting it.

```sh
ssh -o IdentitiesOnly=yes -i "$HOME/.ssh/axiom64-bench" bench@192.168.100.200
sftp -o IdentitiesOnly=yes -i "$HOME/.ssh/axiom64-bench" bench@192.168.100.200
```

At the `sftp>` prompt, use `put sample.bin`, `get sample.bin returned.bin`,
then `bye`. Run `cmp sample.bin returned.bin` on the build PC. `scp` can use
the same account, identity and host key. [OpenSSH sftp manual](https://man.openbsd.org/sftp.1)

If PXE succeeds but SSH cannot connect, check that the guest shows the correct
address and the SSH listener is running. On Windows with WSL or VPN adapters,
check that the client routes `192.168.100.200` through physical Ethernet.

### SSH on an installed desktop

The installed desktop includes OpenSSH. Sign in on the console first and set up
the server on the installed disk. Save the build PC's public key in
`~/.ssh/authorized_keys` with mode `0600` and set the `.ssh` directory to `0700`.
Use a dedicated key for the test machine.

```sh
sudo accountctl group-add sshd 74
sudo accountctl user-add sshd 74 sshd /home/sshd /bin/nologin
sudo ssh-keygen -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
sudo cp /etc/ssh/sshd_config.example /etc/ssh/sshd_config
sudo chmod 600 /etc/ssh/sshd_config
```

Run those commands once. In `/etc/ssh/sshd_config`, set `ListenAddress` to the
Blade's configured wired address and set `AllowUsers` to the account allowed
to connect. For a direct cable with the addresses above, use `192.168.100.200`
and `admin@192.168.100.3`. Then check the configuration and start the server.

```sh
sudo /usr/sbin/sshd -t
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
sudo /usr/sbin/sshd -D -e
```

Connect from the build PC and compare that fingerprint. Use the normal account
name for SSH, SFTP, and SCP. The account setup and keys persist across reboots.
Start the listener again from the console when needed.

## FTP compatibility test

The lab FTP image ran Pure-FTPd on TCP `2121` with a separate `benchftp` account
confined to its home directory. The server used passive data ports `52100` to
`52103`. Enable the service only on the isolated cable and use a disposable
password. Plain FTP exposes credentials and file contents on the wire. Use
SFTP for regular transfers. [FTP and TLS](https://everything.curl.dev/ftp/ftps.html)

The following commands prompt for the FTP password. Run them from the build
PC with a small `sample.bin` file.

```sh
curl --noproxy '*' --user benchftp --ftp-pasv --upload-file sample.bin \
    ftp://192.168.100.200:2121/sample.bin
curl --noproxy '*' --user benchftp --ftp-pasv --output returned.bin \
    ftp://192.168.100.200:2121/sample.bin
cmp sample.bin returned.bin
```

To check active FTP, replace `--ftp-pasv` on both commands with
`--ftp-port 192.168.100.3`. Active mode needs the build PC to accept the
server's data connection on that adapter. The lab checked both modes over
the Blade's direct cable.

### FTP on an installed desktop

For an installed-image FTP check, create a locked local account and a separate
FTP login. Use an unused UID and GID of at least `1001` on the test machine.
`pure-pw` prompts for the FTP password and confines `transfer` to the account's
home directory.

```sh
sudo accountctl group-add benchftp 1001
sudo accountctl user-add benchftp 1001 benchftp /home/benchftp /bin/nologin
sudo /usr/bin/pure-pw useradd transfer -u benchftp -d /home/benchftp -m
sudo /usr/sbin/pure-ftpd -4 -A -E -H -l puredb:/etc/pureftpd.pdb \
    -u 1001 -S 192.168.100.200,2121 -c 2 -p 52100:52103
```

Use `--user transfer` in the client commands above. Stop the listener when the
file check is done. Use `sudo /usr/bin/pure-pw passwd transfer -m` to change
the FTP password before the next run.
