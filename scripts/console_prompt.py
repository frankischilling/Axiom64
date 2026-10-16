"""Locate the installed ordinary Bash prompt in cumulative serial bytes."""
import re

SHELL_PROMPT = re.compile(rb'\x1b\[\?2004hbash-[0-9]+\.[0-9]+\$ ')
KERNEL_RECORD = re.compile(
    rb'(?:exec pid=[0-9]+ [^\r\n]+ \((?:static ELF|dynamic musl)\)|'
    rb'unimplemented syscall [0-9]+ pid=[0-9]+|'
    rb'RANDOM_RESEEDED source=[a-z0-9_-]+ bits=[0-9]+)\r?\n')


def shell_prompt_end(text, start=0):
    # Kernel diagnostics are complete records, but can land between separate
    # userspace writes of one prompt. Preserve the capture and its raw offsets;
    # omit only these known records in the temporary view used for recognition.
    remaining = text[start:]
    filtered, offsets, cursor = bytearray(), [], 0
    for record in KERNEL_RECORD.finditer(remaining):
        filtered.extend(remaining[cursor:record.start()])
        offsets.extend(range(start + cursor, start + record.start()))
        cursor = record.end()
    filtered.extend(remaining[cursor:])
    offsets.extend(range(start + cursor, len(text)))
    match = SHELL_PROMPT.search(filtered)
    return offsets[match.end() - 1] + 1 if match else None
