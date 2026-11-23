# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/tests/auto_eduroam_test.py
# @brief   Verify eduroam profile setup and cancellation.
# @author  frankischilling
# @date    2026-11-23
#
# Exercises the installed script's NetworkManager calls without a radio or a
# saved credential. Distributed under the same license as Axiom64.

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[2] / "vendor/auto-eduroam/connect-eduroam.sh"
TOKEN = "00112233445566778899aabbccddeeff"
UUID = "00112233-4455-6677-8899-aabbccddeeff"
NMCLI = """#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
case = os.environ["TEST_SCENARIO"]
with open(os.environ["TEST_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[-2:] == ["device", "status"]:
    print("enp0s1:ethernet" if case == "no-wifi" else "wlan0:wifi")
elif "list" in args:
    print("eduroam")
elif args[-2:] == ["connection", "show"]:
    if case == "existing":
        print("Axiom64 eduroam")
elif "up" in args and case == "activation-fails":
    sys.exit(4)
"""


class EduroamTest(unittest.TestCase):
    def run_fixture(self, scenario="success", *, valid_certificate=True):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            certificate = work / "school CA.pem"
            if valid_certificate:
                certificate.write_text("Certificate path fixture only\n")
            nmcli = work / "nmcli"
            nmcli.write_text(NMCLI)
            nmcli.chmod(0o755)
            uuidgen = work / "dbus-uuidgen"
            uuidgen.write_text(f"#!/bin/sh\nprintf '%s\\n' {TOKEN}\n")
            uuidgen.chmod(0o755)
            log = work / "commands.jsonl"
            result = subprocess.run(
                ["bash", SCRIPT], text=True, timeout=10, capture_output=True,
                input=f"student@example.edu\n{certificate}\nauth.example.edu\nanonymous@example.edu\n",
                env=dict(os.environ, PATH=f"{work}:{os.environ['PATH']}", TEST_LOG=str(log),
                         TEST_SCENARIO=scenario),
            )
            return result, [json.loads(line) for line in log.read_text().splitlines()], certificate

    def test_verified_profile_leaves_password_to_nmcli(self):
        result, calls, certificate = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        add, up = calls[-2:]
        self.assertEqual(add[:3], ["--ask", "connection", "add"])
        self.assertEqual(add[add.index("802-1x.ca-cert") + 1], str(certificate))
        self.assertEqual(add[add.index("802-1x.domain-suffix-match") + 1], "auth.example.edu")
        self.assertEqual(add[add.index("802-1x.password-flags") + 1], "not-saved")
        self.assertNotIn("802-1x.password", add)
        self.assertEqual(up, ["--ask", "--wait", "60", "connection", "up", "uuid", UUID,
                              "ifname", "wlan0"])

    def test_failed_connection_cleans_up_only_its_own_profile(self):
        result, calls, _ = self.run_fixture("activation-fails")
        self.assertEqual(result.returncode, 4)
        self.assertEqual(calls[-1], ["--wait", "5", "connection", "delete", "uuid", UUID])

    def test_missing_device_certificate_or_existing_profile_blocks_mutation(self):
        for scenario, ca in (("no-wifi", True), ("existing", True), ("success", False)):
            with self.subTest(scenario=scenario, certificate=ca):
                result, calls, _ = self.run_fixture(scenario, valid_certificate=ca)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any("add" in call or "delete" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
