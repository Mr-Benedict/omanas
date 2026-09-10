"""Tests for the privileged helper's validation and fstab handling.

This is the code that runs as root, so the cases that matter are the ones
where a caller lies: a mountpoint outside the home directory, a symlink that
escapes it after the check, a share name carrying a mount option.
"""

import json
import os
import pwd
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

HELPER = os.path.join(os.path.dirname(__file__), "..", "bin", "omanas-mount")
mod = SourceFileLoader("omanas_mount", HELPER).load_module()

ME = pwd.getpwuid(os.getuid())


class Validation(unittest.TestCase):
    def test_share_names(self):
        for good in ["Photos", "home", "Time Machine", "a-b_c.d"]:
            self.assertTrue(mod.SHARE_RE.match(good), good)
        for bad in [
            "",
            "../etc",
            "a/b",
            "a,ro",                      # would smuggle a second mount option
            "a$(id)",
            "a\nb",
            "-leading-dash",
            "x" * 65,
        ]:
            self.assertIsNone(mod.SHARE_RE.match(bad), bad)

    def test_host_names(self):
        for good in ["nas", "nas.local", "192.168.1.20"]:
            self.assertTrue(mod.HOST_RE.match(good), good)
        for bad in ["", "nas/x", "nas,y", "-nas", "nas ", "a" * 255]:
            self.assertIsNone(mod.HOST_RE.match(bad), bad)


class Mountpoints(unittest.TestCase):
    def test_inside_home_is_accepted(self):
        target = os.path.join(ME.pw_dir, "mnt", "nas", "Photos")
        self.assertEqual(mod.checked_mountpoint(ME, target), os.path.realpath(target))

    def test_outside_home_is_refused(self):
        for path in ["/etc", "/", "/tmp/evil", os.path.dirname(ME.pw_dir)]:
            with self.assertRaises(SystemExit, msg=path):
                mod.checked_mountpoint(ME, path)

    def test_home_itself_is_refused(self):
        with self.assertRaises(SystemExit):
            mod.checked_mountpoint(ME, ME.pw_dir)

    def test_traversal_is_refused(self):
        with self.assertRaises(SystemExit):
            mod.checked_mountpoint(ME, os.path.join(ME.pw_dir, "..", "..", "etc"))

    def test_symlink_escape_is_refused(self):
        """realpath must run before the check, not after."""
        with tempfile.TemporaryDirectory(dir=ME.pw_dir) as sandbox:
            link = os.path.join(sandbox, "escape")
            os.symlink("/etc", link)
            with self.assertRaises(SystemExit):
                mod.checked_mountpoint(ME, link)


class FstabHarness:
    """Shared fixture: a scratch fstab with foreign lines that must survive."""

    OTHERS = [
        "UUID=1111  /      btrfs  noatime,subvol=@      0 0",
        "UUID=2222  /home  btrfs  noatime,subvol=@home  0 0",
    ]

    def setUp(self):
        handle, self.path = tempfile.mkstemp()
        os.close(handle)
        self.addCleanup(os.remove, self.path)
        self._real = mod.FSTAB
        mod.FSTAB = self.path
        self.addCleanup(setattr, mod, "FSTAB", self._real)
        with open(self.path, "w") as stream:
            stream.write("\n".join(self.OTHERS) + "\n")

    def read(self):
        with open(self.path) as stream:
            return stream.read().splitlines()


class Fstab(FstabHarness, unittest.TestCase):
    """The managed block must be the only thing touched."""

    def test_untouched_when_no_block(self):
        outside, managed = mod.read_fstab()
        self.assertEqual(outside, self.OTHERS)
        self.assertEqual(managed, [])

    def test_roundtrip_preserves_foreign_lines(self):
        entry = mod.fstab_entry(ME, "nas", "Photos",
                                os.path.join(ME.pw_dir, "mnt/nas/Photos"),
                                "/home/x/.config/omanas/creds-Photos", False)
        mod.write_fstab(self.OTHERS, [entry])
        lines = self.read()
        for original in self.OTHERS:
            self.assertIn(original, lines)
        self.assertIn(mod.BEGIN, lines)
        self.assertIn(mod.END, lines)

        outside, managed = mod.read_fstab()
        self.assertEqual(outside, self.OTHERS)
        self.assertEqual(managed, [entry])

    def test_removing_the_block_restores_the_original_file(self):
        entry = mod.fstab_entry(ME, "nas", "Photos",
                                os.path.join(ME.pw_dir, "mnt/nas/Photos"),
                                "/home/x/creds", False)
        mod.write_fstab(self.OTHERS, [entry])
        outside, _ = mod.read_fstab()
        mod.write_fstab(outside, [])
        self.assertEqual(self.read(), self.OTHERS)

    def test_share_with_spaces_is_escaped(self):
        target = os.path.join(ME.pw_dir, "mnt/nas/Time Machine")
        entry = mod.fstab_entry(ME, "nas", "Time Machine", target, "/home/x/creds", False)
        self.assertIn("Time\\040Machine", entry)
        self.assertNotIn("Time Machine", entry)
        # Six whitespace-separated fields, or mount will misread the line.
        self.assertEqual(len(entry.split()), 6)


class CallerIdentity(unittest.TestCase):
    def test_refuses_without_pkexec_uid(self):
        env = {k: v for k, v in os.environ.items() if k != "PKEXEC_UID"}
        result = subprocess.run(
            [sys.executable, HELPER, "unmount", "--mountpoint", "/tmp/x"],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PKEXEC_UID", json.loads(result.stdout)["error"])

    def test_refuses_bogus_pkexec_uid(self):
        env = dict(os.environ, PKEXEC_UID="999999")
        result = subprocess.run(
            [sys.executable, HELPER, "unmount", "--mountpoint", "/tmp/x"],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("real user", json.loads(result.stdout)["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class FstabStability(FstabHarness, unittest.TestCase):
    """Writing the block repeatedly must not make the file grow."""

    def test_repeated_cycles_are_idempotent(self):
        entry = mod.fstab_entry(ME, "nas", "Photos",
                                os.path.join(ME.pw_dir, "mnt/nas/Photos"),
                                "/home/x/creds", False)
        shapes = []
        for _ in range(5):
            outside, _ = mod.read_fstab()
            mod.write_fstab(outside, [entry])
            shapes.append(self.read())
        self.assertEqual(shapes[0], shapes[-1])
        self.assertEqual(shapes[-1].count(""), shapes[0].count(""))

    def test_forget_after_persist_leaves_no_residue(self):
        target = os.path.join(ME.pw_dir, "mnt/nas/Time Machine")
        entry = mod.fstab_entry(ME, "nas", "Time Machine", target, "/home/x/creds", False)
        mod.write_fstab(self.OTHERS, [entry])
        outside, managed = mod.read_fstab()
        # The space-escaped entry must still be findable by its real path.
        kept = [line for line in managed if mod.entry_target(line) != target]
        self.assertEqual(kept, [])
        mod.write_fstab(outside, kept)
        self.assertEqual(self.read(), self.OTHERS)
