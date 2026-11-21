#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/pcm_test.py
# @brief   Check Intel HD Audio through booted QEMU guests.
# @author  frankischilling
# @date    2026-11-21
#
# Captures guest playback and supplies an independent sample source.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.

"""Check HD Audio playback and capture across the guest and QEMU boundary."""
import argparse
from collections import Counter
from itertools import product
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import wave

from account_normal_test import write_cpio
from boot_media_test import digest
from fetch import ROOT
from legacy_ata_test import image


def boot(output, machine, firmware, codec, mode):
    directory = output / f"{machine}-{firmware}-{mode}"
    directory.mkdir()
    command = [
        "qemu-system-x86_64", "-machine", machine, "-cpu", "max", "-m", "384M",
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot", "-nic", "none",
        "-boot", "order=d,strict=on", "-device", "isa-debug-exit,iobase=0xf4,iosize=4",
        "-cdrom", str(output / f"audio-{mode}.iso"),
    ]
    if codec:
        command += ["-device", f"{codec},id=hda"]
    environment = os.environ.copy()
    if mode == "playback":
        command += ["-audiodev", f"wav,id=pcm,path={directory / 'output.wav'},out.frequency=48000",
                    "-device", "hda-output,bus=hda.0,audiodev=pcm"]
    if mode == "capture":
        source = directory / "input.raw"
        audio = b"".join(struct.pack("<hh", n, -n // 2) for i in range(48000 * 20)
                         for n in (6200 if i % 64 < 32 else -6200,))
        source.write_bytes(audio)
        config = directory / "alsa.conf"
        config.write_text('pcm.axiom_in { type file slave.pcm { type null } format raw '
                          f'file "/dev/null" infile "{source}" }}\n'
                          'pcm.axiom_out { type file slave.pcm { type null } format raw '
                          f'file "{directory / "duplex.raw"}" }}\n')
        environment["ALSA_CONFIG_PATH"] = str(config)
        command += ["-audiodev", "alsa,id=pcm,in.dev=axiom_in,out.dev=axiom_out,"
                    "in.buffer-length=10666,in.period-length=5333,in.try-poll=off,"
                    "out.frequency=48000,out.try-poll=off",
                    "-device", "hda-duplex,bus=hda.0,audiodev=pcm,use-timer=off"]
    if firmware == "uefi":
        variables = directory / "VARS.fd"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", variables)
        command += ["-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
    (directory / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    log = directory / "serial.log"
    with log.open("wb") as serial:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=serial,
                                stderr=subprocess.STDOUT, timeout=60, env=environment)
    serial = log.read_text(errors="replace")
    if (result.returncode != 1 or f"Firmware: {firmware.upper()}" not in serial or
            "AXIOM64_EXIT status=0" not in serial or f"PCM_{mode.upper()}_PASS" not in serial or
            any(marker in serial for marker in ("PCM_FAIL", "FAULT pid=", "PANIC:"))):
        raise RuntimeError(f"{directory.name}: status {result.returncode}; see {log}")
    record = dict(name=directory.name, serial_sha256=digest(log),
                  iso_sha256=digest(output / f"audio-{mode}.iso"))
    if mode == "playback":
        record.update(verify_audio(directory / "output.wav"))
    if mode == "capture":
        duplex = directory / "duplex.raw"
        frames = sum(abs(l) == 7500 and abs(r) == 3500
                     for l, r in struct.iter_unpack("<hh", duplex.read_bytes()))
        if frames < 1000 or serial.count("hda: capture overrun") != 1:
            raise RuntimeError(f"{directory.name}: duplex signal or capture recovery missing")
        record.update(duplex_sha256=digest(duplex), duplex_frames=frames,
                      input_sha256=digest(directory / "input.raw"))
    print(f"{directory.name}: passed", flush=True)
    return record


def verify_audio(path):
    with wave.open(str(path), "rb") as wav:
        if (wav.getframerate(), wav.getsampwidth(), wav.getnchannels()) != (48000, 2, 2):
            raise RuntimeError(f"{path}: unexpected WAV format")
        frames = list(struct.iter_unpack("<hh", wav.readframes(wav.getnframes())))
    levels = [4600 + i * 410 for i in range(8)]
    stereo = [abs(l) for l, r in frames if abs(l) in levels and abs(l) == 2 * abs(r)]
    counts = Counter(stereo)
    mono = sum(l == r and abs(l) in (5299, 5300) for l, r in frames)
    if (any(not 3500 <= counts[level] <= 6050 for level in levels) or
            stereo != sorted(stereo) or len(stereo) < 41000 or not 2500 <= mono <= 4459):
        raise RuntimeError(f"{path}: unexpected PCM envelope, counts {counts}, mono {mono}")
    return dict(wav_sha256=digest(path), stereo_frames=len(stereo), mono_frames=mono,
                amplitude_counts={str(level): counts[level] for level in levels})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "build/pcm-test")
    parser.add_argument("--mode", choices=("absent", "playback", "capture"), action="append")
    options = parser.parse_args()
    modes = options.mode or ("absent", "playback", "capture")
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    subprocess.run(["make", "-j2", "build/axiom64.elf"], cwd=ROOT, check=True)
    init = output / "init"
    subprocess.run(["musl-gcc", "-static", "-Wall", "-Wextra", "-Werror",
                    ROOT / "userspace/tests/desktop/pcm.c", "-o", init], check=True)
    for mode in modes:
        cpio = output / f"{mode}.cpio"
        files = {"dev": (0o40755, b""), "sbin": (0o40755, b""),
                 "sbin/init": (0o100755, init.read_bytes())}
        if mode != "playback":
            files["no-audio" if mode == "absent" else mode] = (0o100644, b"")
        write_cpio(cpio, files)
        image(output, cpio, name=f"audio-{mode}.iso")
    cases = []
    for mode in modes:
        for machine, firmware in product(("pc", "q35"), ("bios", "uefi")):
            codec = "ich9-intel-hda" if machine == "q35" else "intel-hda"
            cases.append(boot(output, machine, firmware, codec if mode != "absent" or machine == "q35"
                              else None, mode))
    (output / "results.json").write_text(json.dumps(
        dict(kernel_sha256=digest(ROOT / "build/axiom64.elf"), cases=cases), indent=2) + "\n")


if __name__ == "__main__":
    main()
