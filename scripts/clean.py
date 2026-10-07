#!/usr/bin/env python3
"""Delete only the resolved build directory inside this workspace."""
import shutil
from fetch import ROOT

target = (ROOT / "build").resolve()
if target.parent != ROOT.resolve() or target.name != "build":
    raise RuntimeError("refusing to remove an unexpected directory")
if target.exists():
    shutil.rmtree(target)
