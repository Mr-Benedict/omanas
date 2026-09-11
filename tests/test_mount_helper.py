"""Tests for the privileged helper's validation and fstab handling.

This is the code that runs as root, so the cases that matter are the ones
where a caller lies: a mountpoint outside the home directory, a symlink that
escapes it after the check, a share name carrying a mount option.
"""

import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from helpers import MOUNT_HELPER as HELPER, omanas_mount, quiet

mod = omanas_mount()

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
            with self.subTest(path=path), quiet(), self.assertRaises(SystemExit):
                mod.checked_mountpoint(ME, path)

    def test_home_itself_is_refused(self):
        with quiet(), self.assertRaises(SystemExit):
            mod.checked_mountpoint(ME, ME.pw_dir)

    def test_traversal_is_refused(self):
        with quiet(), self.assertRaises(SystemExit):
            mod.checked_mountpoint(ME, os.path.join(ME.pw_dir, "..", "..", "etc"))

    def test_symlink_escape_is_refused(self):
        """realpath must run before the check, not after."""
        with tempfile.TemporaryDirectory(dir=ME.pw_dir) as sandbox:
            link = os.path.join(sandbox, "escape")
            os.symlink("/etc", link)
            with quiet(), self.assertRaises(SystemExit):
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


class AccountNames(unittest.TestCase):
    """The account name is written into a credentials file mount.cifs reads."""

    def test_accepted(self):
        for good in ["ben", "ben.gaetani", "ben_1", "ben@nas.local", "a-b"]:
            self.assertTrue(mod.USER_RE.match(good), good)

    def test_refused(self):
        for bad in [
            "",
            "-ben",
            "ben\npassword=x",   # would inject a second credentials field
            "ben/x",
            "ben x",
            "b" * 65,
        ]:
            self.assertIsNone(mod.USER_RE.match(bad), repr(bad))


class MountOptions(unittest.TestCase):
    """A share is someone else's filesystem; it gets no say over this machine."""

    def test_the_hardening_flags_are_not_optional(self):
        options = mod.mount_options(ME, False).split(",")
        for flag in ["nosuid", "nodev", "noexec"]:
            self.assertIn(flag, options)

    def test_smb1_is_never_negotiated(self):
        # SMB1 is broken badly enough that declining to fall back is worth
        # pinning in a test rather than leaving to mount.cifs's default.
        self.assertIn("vers=3.0", mod.mount_options(ME, False).split(","))

    def test_the_mount_belongs_to_the_caller_not_to_root(self):
        options = mod.mount_options(ME, False)
        self.assertIn(f"uid={ME.pw_uid}", options)
        self.assertIn(f"gid={ME.pw_gid}", options)

    def test_only_the_caller_can_read_it(self):
        options = mod.mount_options(ME, False)
        self.assertIn("file_mode=0700", options)
        self.assertIn("dir_mode=0700", options)

    def test_read_only_is_added_only_when_asked(self):
        self.assertNotIn("ro", mod.mount_options(ME, False).split(","))
        self.assertIn("ro", mod.mount_options(ME, True).split(","))


class FstabEntries(unittest.TestCase):
    TARGET = os.path.join(ME.pw_dir, "mnt/nas/Photos")

    def entry(self, read_only=False, share="Photos"):
        return mod.fstab_entry(ME, "nas.local", share, self.TARGET,
                               "/home/x/.config/omanas/creds-Photos", read_only)

    def test_it_does_not_mount_at_boot(self):
        # A NAS that is off, or a laptop away from home, must not hold up the
        # boot waiting for a share.
        options = self.entry().split()[3].split(",")
        self.assertIn("noauto", options)
        self.assertIn("_netdev", options)

    def test_the_owner_can_mount_it_without_pkexec(self):
        # This is the entire point of persisting: 'user' plus Arch's setuid
        # mount.cifs is what makes every later mount prompt-free.
        self.assertIn("user", self.entry().split()[3].split(","))

    def test_the_password_is_referenced_rather_than_written(self):
        entry = self.entry()
        self.assertIn("credentials=", entry)
        self.assertNotIn("password=", entry)

    def test_the_hardening_flags_survive_into_fstab(self):
        options = self.entry().split()[3].split(",")
        for flag in ["nosuid", "nodev", "noexec", "vers=3.0"]:
            self.assertIn(flag, options)

    def test_read_only_carries_through(self):
        self.assertIn("ro", self.entry(read_only=True).split()[3].split(","))

    def test_six_fields_exactly(self):
        # mount reads fstab positionally; a stray space makes a different line.
        self.assertEqual(len(self.entry().split()), 6)
        self.assertEqual(self.entry().split()[2], "cifs")
        self.assertEqual(self.entry().split()[-2:], ["0", "0"])

    def test_entry_target_reads_the_mountpoint_back(self):
        self.assertEqual(mod.entry_target(self.entry()), self.TARGET)

    def test_entry_target_undoes_the_escaping(self):
        target = os.path.join(ME.pw_dir, "mnt/nas/Time Machine")
        entry = mod.fstab_entry(ME, "nas.local", "Time Machine", target, "/creds", False)
        # Matching by the raw path missed every share with a space in it, so
        # 'forget' silently did nothing for shares like this one.
        self.assertEqual(mod.entry_target(entry), target)

    def test_entry_target_tolerates_a_line_with_no_mountpoint(self):
        self.assertEqual(mod.entry_target(""), "")
        self.assertEqual(mod.entry_target("//nas/Photos"), "")


class FstabEdgeCases(FstabHarness, unittest.TestCase):
    def test_a_begin_marker_without_an_end_is_left_alone(self):
        # Half a block means someone edited the file by hand. Rewriting from
        # a guess is how a managed block eats the line below it.
        with open(self.path, "w") as stream:
            stream.write("\n".join(self.OTHERS + [mod.BEGIN, "//nas/x /m cifs noauto 0 0"]) + "\n")
        outside, managed = mod.read_fstab()
        self.assertEqual(managed, [])
        self.assertIn(mod.BEGIN, outside)

    def test_an_empty_fstab(self):
        with open(self.path, "w") as stream:
            stream.write("")
        self.assertEqual(mod.read_fstab(), ([], []))

    def test_comments_and_blank_lines_outside_the_block_survive(self):
        original = ["# /etc/fstab: static file system information", "",
                    *self.OTHERS, "", "# scratch", "tmpfs /tmp tmpfs defaults 0 0"]
        with open(self.path, "w") as stream:
            stream.write("\n".join(original) + "\n")
        outside, _ = mod.read_fstab()
        entry = mod.fstab_entry(ME, "nas", "Photos",
                                os.path.join(ME.pw_dir, "mnt/nas/Photos"), "/creds", False)
        mod.write_fstab(outside, [entry])
        lines = self.read()
        for line in original:
            if line.strip():
                self.assertIn(line, lines)

    def test_the_file_always_ends_in_exactly_one_newline(self):
        mod.write_fstab(self.OTHERS, [])
        with open(self.path) as stream:
            text = stream.read()
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))

    def test_the_written_file_is_world_readable(self):
        # /etc/fstab is 0644 by convention and plenty of tools read it.
        mod.write_fstab(self.OTHERS, [])
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o644)

    def test_a_second_share_joins_the_same_block(self):
        first = mod.fstab_entry(ME, "nas", "Photos",
                                os.path.join(ME.pw_dir, "mnt/nas/Photos"), "/creds", False)
        second = mod.fstab_entry(ME, "nas", "Backups",
                                 os.path.join(ME.pw_dir, "mnt/nas/Backups"), "/creds", False)
        mod.write_fstab(self.OTHERS, [first, second])
        lines = self.read()
        self.assertEqual(lines.count(mod.BEGIN), 1)
        _, managed = mod.read_fstab()
        self.assertEqual(managed, [first, second])

    def test_re_persisting_a_share_replaces_its_entry(self):
        target = os.path.join(ME.pw_dir, "mnt/nas/Photos")
        old = mod.fstab_entry(ME, "nas", "Photos", target, "/creds", False)
        new = mod.fstab_entry(ME, "nas", "Photos", target, "/creds", True)
        mod.write_fstab(self.OTHERS, [old])
        _, managed = mod.read_fstab()
        managed = [line for line in managed if mod.entry_target(line) != target] + [new]
        mod.write_fstab(self.OTHERS, managed)
        _, managed = mod.read_fstab()
        self.assertEqual(managed, [new])

    @unittest.skipUnless(shutil.which("findmnt"), "findmnt is not installed")
    def test_a_malformed_entry_is_refused_rather_than_written(self):
        # A corrupt fstab is an unbootable machine, so the replacement has to
        # parse before it is allowed to take the real file's place.
        before = self.read()
        with quiet(), self.assertRaises(SystemExit):
            mod.write_fstab(self.OTHERS, ["this is not an fstab line at all"])
        self.assertEqual(self.read(), before)

    @unittest.skipUnless(shutil.which("findmnt"), "findmnt is not installed")
    def test_an_unreachable_share_is_not_treated_as_malformed(self):
        # findmnt --verify warns about anything it cannot reach right now,
        # and exits non-zero for warnings. Treating that as failure would
        # have refused every legitimate persist, since the whole point is a
        # share that is not mounted yet.
        entry = mod.fstab_entry(ME, "nowhere.invalid", "Photos",
                                os.path.join(ME.pw_dir, "mnt/nas/Photos"), "/creds", False)
        mod.write_fstab(self.OTHERS, [entry])
        self.assertIn(entry, self.read())


class HelperProcess(unittest.TestCase):
    """Run the helper as the panel's chain actually runs it."""

    def run_helper(self, argv, uid=None, stdin=""):
        env = dict(os.environ)
        env.pop("PKEXEC_UID", None)
        if uid is not None:
            env["PKEXEC_UID"] = str(uid)
        return subprocess.run([sys.executable, HELPER, *argv], input=stdin,
                              capture_output=True, text=True, env=env)

    def test_every_failure_path_still_answers_in_json(self):
        # The caller parses the last line of stdout. A traceback there is a
        # mount that silently did nothing as far as the panel can tell.
        result = self.run_helper(["unmount", "--mountpoint", "/etc"], uid=os.getuid())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["ok"])

    def test_list_works_and_reports_the_managed_block(self):
        result = self.run_helper(["list"], uid=os.getuid())
        self.assertEqual(result.returncode, 0)
        answer = json.loads(result.stdout)
        self.assertTrue(answer["ok"])
        self.assertIsInstance(answer["entries"], list)

    def test_a_subcommand_is_required(self):
        self.assertNotEqual(self.run_helper([], uid=os.getuid()).returncode, 0)

    def test_a_share_name_carrying_a_mount_option_is_refused(self):
        result = self.run_helper(
            ["mount", "--host", "nas", "--share", "Photos,ro,uid=0",
             "--mountpoint", os.path.join(ME.pw_dir, "mnt/x"), "--account", "ben"],
            uid=os.getuid(), stdin="hunter2\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("share", json.loads(result.stdout)["error"].lower())

    def test_the_mountpoint_is_checked_before_the_password_is_read(self):
        # Refusing early means a crafted request never gets to hold a
        # credential in this process at all.
        result = self.run_helper(
            ["mount", "--host", "nas", "--share", "Photos",
             "--mountpoint", "/etc", "--account", "ben"],
            uid=os.getuid(), stdin="hunter2\n")
        self.assertIn("Refusing", json.loads(result.stdout)["error"])

    def test_the_executable_bit_is_set(self):
        # pkexec runs it directly.
        self.assertTrue(os.stat(HELPER).st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
