# SPDX-License-Identifier: GPL-3.0-or-later
"""Clone immutable evidence for serialized controls without changing owners."""
import os
from pathlib import Path
import shutil


def copy_input(source, destination):
    if os.geteuid() == 0:
        return os.link(source, destination)
    # Native receipts and bounded kernel-config proof files must remain regular.
    # Copies remain private to the ordinary reader; other immutable inputs
    # can be referenced until a control replaces its reference before writing.
    if Path(source).name.endswith('.clocks.jsonl') or Path(source).stat().st_size <= 1048576:
        return shutil.copy2(source, destination)
    return os.symlink(source, destination)
