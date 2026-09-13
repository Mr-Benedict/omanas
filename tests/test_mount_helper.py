"""Tests for the privileged helper's path handling, tools and fstab writing.

This is the code that runs as root, so the cases that matter are the ones
where a caller lies: a share name carrying a mount option, a symlink standing
where a directory should be, a tool that never returns, an fstab that changed
underneath us.

Everything here runs as an ordinary user. That is possible because the
helper's ownership check asks whether a directory belongs to the identity it
is running as, rather than hard-coding uid 0, so a sandbox of the test user's
own directories exercises the same code root would take.
"""

import argparse
import contextlib
import io
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from helpers import MOUNT_HELPER as HELPER, omanas_mount, quiet

mod = omanas_mount()

ME = pwd.getpwuid(os.getuid())
HAVE_FINDMNT = bool(shutil.which("findmnt"))


def refusal(buffer):
    """The error the helper printed on its way out."""
    return json.loads(buffer.getvalue().strip().splitlines()[-1])["error"]


class Sandbox:
    """A whole root-owned path chain, except that here we are the root.

    ROOT, MOUNT_BASE, STATE_DIR and RUNTIME_DIR move into a directory this
    user owns, which is what lets the descriptor walk be tested at all.
    """

    def setUp(self):
        super().setUp()
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.swap("ROOT", self.root)
        self.swap("MOUNT_BASE", os.path.join(self.root, "mnt", "omanas"))
        self.swap("STATE_DIR", os.path.join(self.root, "etc", "omanas"))
        self.swap("RUNTIME_DIR", os.path.join(self.root, "run", "omanas"))

    def swap(self, name, value):
        self.addCleanup(setattr, mod, name, getattr(mod, name))
        setattr(mod, name, value)

    def mountinfo(self, *lines):
        path = os.path.join(self.root, "mountinfo")
        with open(path, "w") as stream:
            stream.write("".join(line + "\n" for line in lines))
        self.swap("MOUNTINFO", path)
        return path


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


class AccountNames(unittest.TestCase):
    """The account name is written into a credentials file mount.cifs reads."""

    def test_accepted(self):
        for good in ["admin", "backup.svc", "nas_1", "admin@example.net", "a-b"]:
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


class OwnDirectories(Sandbox, unittest.TestCase):
    """require_own_dir is the gate every component of every chain passes."""

    def open_dir(self, mode):
        path = os.path.join(self.root, f"d{mode:o}")
        os.mkdir(path)
        os.chmod(path, mode)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        return fd

    def test_our_own_private_directory_is_accepted(self):
        mod.require_own_dir(self.open_dir(0o700), "sandbox")
        mod.require_own_dir(self.open_dir(0o755), "sandbox")

    def test_group_writable_is_refused(self):
        # A directory the caller's group can write to is a directory the
        # caller can replace a component of.
        with quiet() as out, self.assertRaises(SystemExit):
            mod.require_own_dir(self.open_dir(0o770), "sandbox")
        self.assertIn("write", refusal(out))

    def test_world_writable_is_refused(self):
        with quiet() as out, self.assertRaises(SystemExit):
            mod.require_own_dir(self.open_dir(0o777), "sandbox")
        self.assertIn("write", refusal(out))

    def test_somebody_elses_directory_is_refused(self):
        # /tmp belongs to root and is writable by everyone: whichever of the
        # two checks fires first, this must not be walked through.
        fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with quiet() as out, self.assertRaises(SystemExit):
            mod.require_own_dir(fd, "/tmp")
        self.assertIn("Refusing to use /tmp", refusal(out))

    def test_a_file_is_not_a_directory(self):
        path = os.path.join(self.root, "plain")
        with open(path, "w"):
            pass
        fd = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with quiet() as out, self.assertRaises(SystemExit):
            mod.require_own_dir(fd, "plain")
        self.assertIn("not a directory", refusal(out))


class Descend(Sandbox, unittest.TestCase):
    """One component at a time, and never through a symlink."""

    def setUp(self):
        super().setUp()
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def test_an_existing_directory_is_opened(self):
        os.mkdir(os.path.join(self.root, "real"))
        child = mod.descend(self.fd, "real", None)
        self.addCleanup(os.close, child)
        self.assertEqual(os.fstat(child).st_ino,
                         os.stat(os.path.join(self.root, "real")).st_ino)

    def test_a_symlink_component_is_refused(self):
        # This is the bug: a symlink here used to send root's mkdir, chown
        # and mount somewhere the caller chose.
        os.symlink("/etc", os.path.join(self.root, "escape"))
        with quiet() as out, self.assertRaises(SystemExit):
            mod.descend(self.fd, "escape", 0o755)
        self.assertIn("symbolic link", refusal(out))

    def test_a_symlink_to_a_directory_we_own_is_still_refused(self):
        os.mkdir(os.path.join(self.root, "genuine"))
        os.symlink(os.path.join(self.root, "genuine"),
                   os.path.join(self.root, "pointer"))
        with quiet() as out, self.assertRaises(SystemExit):
            mod.descend(self.fd, "pointer", 0o755)
        self.assertIn("symbolic link", refusal(out))

    def test_a_plain_file_is_refused(self):
        with open(os.path.join(self.root, "file"), "w"):
            pass
        with quiet() as out, self.assertRaises(SystemExit):
            mod.descend(self.fd, "file", 0o755)
        self.assertIn("not a directory", refusal(out))

    def test_a_missing_component_is_created_when_a_mode_is_given(self):
        child = mod.descend(self.fd, "fresh", 0o755)
        self.addCleanup(os.close, child)
        self.assertTrue(os.path.isdir(os.path.join(self.root, "fresh")))

    def test_a_missing_component_is_not_created_otherwise(self):
        with quiet(), self.assertRaises(SystemExit):
            mod.descend(self.fd, "absent", None)

    def test_the_mode_is_set_through_the_descriptor_not_the_name(self):
        # os.chmod on a name resolves that name again and follows a symlink,
        # so anything that won the race between the ENOENT and the mkdir
        # would have had root change the mode of whatever it pointed at. The
        # descriptor was opened with O_NOFOLLOW and cannot be redirected, so
        # nothing on this path may go through the name at all.
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        self.addCleanup(setattr, os, "chmod", os.chmod)

        def refuse(*args, **kwargs):
            raise AssertionError("descend changed the mode by name")

        os.chmod = refuse
        child = mod.descend(self.fd, "fresh", 0o755)
        self.addCleanup(os.close, child)
        self.assertEqual(os.fstat(child).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(os.path.join(self.root, "fresh")).st_mode & 0o777,
                         0o755)


class Chains(Sandbox, unittest.TestCase):
    def test_the_whole_chain_is_created(self):
        fd = mod.open_chain(mod.MOUNT_BASE, 0o755)
        self.addCleanup(os.close, fd)
        self.assertTrue(os.path.isdir(mod.MOUNT_BASE))

    def test_the_mode_survives_a_hostile_umask(self):
        # mkdir's mode goes through the umask, so asking for 0755 under a
        # 0077 umask would otherwise leave 0700 -- and under a 0000 umask a
        # request for 0700 would leave a world-writable directory.
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        fd = mod.open_chain(os.path.join(self.root, "a", "b"), 0o755)
        self.addCleanup(os.close, fd)
        self.assertEqual(os.stat(os.path.join(self.root, "a")).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(os.path.join(self.root, "a", "b")).st_mode & 0o777, 0o755)

    def test_a_private_mode_survives_a_slack_umask(self):
        previous = os.umask(0o000)
        self.addCleanup(os.umask, previous)
        fd = mod.open_chain(mod.STATE_DIR, 0o700)
        self.addCleanup(os.close, fd)
        self.assertEqual(os.stat(mod.STATE_DIR).st_mode & 0o777, 0o700)

    def test_a_symlink_anywhere_on_the_chain_stops_it(self):
        os.mkdir(os.path.join(self.root, "mnt"))
        os.symlink("/etc", os.path.join(self.root, "mnt", "omanas"))
        with quiet() as out, self.assertRaises(SystemExit):
            mod.open_chain(mod.MOUNT_BASE, 0o755)
        self.assertIn("symbolic link", refusal(out))

    def test_a_path_outside_the_root_is_refused(self):
        with quiet(), self.assertRaises(SystemExit):
            mod.open_chain("/etc/passwd", 0o755)


class Mountpoints(Sandbox, unittest.TestCase):
    """The caller names a share; the helper decides where it goes."""

    def test_the_path_is_derived_not_supplied(self):
        self.assertEqual(mod.mountpoint_path(ME, "Photos"),
                         os.path.join(mod.MOUNT_BASE, ME.pw_name, "Photos"))

    def test_a_share_name_that_could_traverse_is_refused(self):
        for bad in ["../../etc", "a/b", ".."]:
            with self.subTest(bad=bad), quiet(), self.assertRaises(SystemExit):
                mod.mountpoint_path(ME, bad)

    def test_opening_it_creates_the_chain_and_keeps_it_open(self):
        point = mod.mountpoint_for(ME, "Time Machine")
        self.addCleanup(point.close)
        self.assertTrue(os.path.isdir(point.path))
        self.assertEqual(os.fstat(point.fd).st_ino, os.stat(point.path).st_ino)
        self.assertEqual(os.listdir(point.fd), [])

    def test_remove_takes_the_directory_back(self):
        point = mod.mountpoint_for(ME, "Photos")
        self.addCleanup(point.close)
        point.remove()
        self.assertFalse(os.path.exists(point.path))

    def test_remove_tolerates_a_directory_that_is_not_empty(self):
        point = mod.mountpoint_for(ME, "Photos")
        self.addCleanup(point.close)
        with open(os.path.join(point.path, "stray"), "w"):
            pass
        point.remove()
        self.assertTrue(os.path.isdir(point.path))


class Credentials(Sandbox, unittest.TestCase):
    def test_the_name_is_a_single_component_without_spaces(self):
        name = mod.credentials_name(ME, "Time Machine")
        # A space would end the credentials= option early and hand the rest
        # of the line to mount as a separate field.
        self.assertNotIn(" ", name)
        self.assertNotIn("/", name)
        self.assertEqual(os.path.basename(name), name)

    def test_the_name_is_stable_for_the_same_share(self):
        self.assertEqual(mod.credentials_name(ME, "Photos"),
                         mod.credentials_name(ME, "Photos"))

    def test_shares_that_flatten_to_the_same_text_still_differ(self):
        # 'Time Machine' and 'Time_Machine' both sanitise to the same
        # readable part; the digest is what keeps the two files apart.
        self.assertNotEqual(mod.credentials_name(ME, "Time Machine"),
                            mod.credentials_name(ME, "Time_Machine"))

    def test_the_file_is_created_private_and_never_through_a_symlink(self):
        state_fd = mod.open_chain(mod.STATE_DIR, 0o700)
        self.addCleanup(os.close, state_fd)
        name = mod.credentials_name(ME, "Photos")
        self.assertTrue(mod.write_credentials(state_fd, name, "ben", "hunter2"))
        path = os.path.join(mod.STATE_DIR, name)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as stream:
            self.assertEqual(stream.read(), "username=ben\npassword=hunter2\n")

    def test_a_second_write_replaces_the_file_and_says_it_did_not_create_it(self):
        # Which of the two it was decides whether a failed persist may take
        # the file away again: one that was already there is named by an
        # fstab entry that is already committed.
        state_fd = mod.open_chain(mod.STATE_DIR, 0o700)
        self.addCleanup(os.close, state_fd)
        name = mod.credentials_name(ME, "Photos")
        mod.write_credentials(state_fd, name, "ben", "hunter2")
        self.assertFalse(mod.write_credentials(state_fd, name, "ben", "hunter3"))
        with open(os.path.join(mod.STATE_DIR, name)) as stream:
            self.assertEqual(stream.read(), "username=ben\npassword=hunter3\n")

    def test_a_symlink_in_the_way_is_refused_rather_than_followed(self):
        state_fd = mod.open_chain(mod.STATE_DIR, 0o700)
        self.addCleanup(os.close, state_fd)
        victim = os.path.join(self.root, "victim")
        with open(victim, "w") as stream:
            stream.write("important\n")
        os.symlink(victim, os.path.join(mod.STATE_DIR, "creds"))
        with quiet(), self.assertRaises(SystemExit):
            mod.write_credentials(state_fd, "creds", "ben", "hunter2")
        with open(victim) as stream:
            self.assertEqual(stream.read(), "important\n")


class MountTable(Sandbox, unittest.TestCase):
    """What the kernel says is mounted, not what a path check guesses."""

    LINES = [
        "23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw",
        "24 28 0:21 / /sys rw,nosuid - sysfs sysfs rw",
        "41 28 0:38 / /mnt/omanas/ben/Time\\040Machine rw,relatime shared:1 "
        "- cifs //nas/Time\\040Machine rw,vers=3.0,uid=1000",
        "not a mountinfo line",
    ]

    def test_it_reads_the_fields_the_separator_marks(self):
        self.mountinfo(*self.LINES)
        table = mod.mount_table()
        self.assertIn(("/proc", "proc", "proc"), table)
        # No optional field at all, so the '-' is field 6 itself.
        self.assertIn(("/sys", "sysfs", "sysfs"), table)

    def test_escaped_spaces_come_back_as_spaces(self):
        self.mountinfo(*self.LINES)
        self.assertIn(("/mnt/omanas/ben/Time Machine", "cifs", "//nas/Time Machine"),
                      mod.mount_table())

    def test_a_line_it_cannot_parse_is_skipped_rather_than_fatal(self):
        self.mountinfo(*self.LINES)
        self.assertEqual(len(mod.mount_table()), 3)

    def test_unescape_handles_the_other_escapes(self):
        self.assertEqual(mod.unescape("a\\011b"), "a\tb")
        self.assertEqual(mod.unescape("a\\134b"), "a\\b")
        self.assertEqual(mod.unescape("plain"), "plain")

    def test_mounted_at_is_an_exact_match(self):
        self.mountinfo(*self.LINES)
        self.assertTrue(mod.mounted_at("/mnt/omanas/ben/Time Machine"))
        self.assertFalse(mod.mounted_at("/mnt/omanas/ben"))
        self.assertFalse(mod.mounted_at("/mnt/omanas/ben/Time\\040Machine"))


class Tools(unittest.TestCase):
    def test_only_absolute_paths_from_known_directories(self):
        found = mod.tool("sh")
        self.assertTrue(os.path.isabs(found))
        self.assertTrue(any(found.startswith(d + "/") for d in mod.TOOL_DIRS))

    def test_a_missing_tool_is_a_clean_refusal(self):
        with quiet() as out, self.assertRaises(SystemExit):
            mod.tool("definitely-not-a-real-tool")
        self.assertIn("not installed", refusal(out))


class BoundedRuns(unittest.TestCase):
    """A root process must not be stalled or flooded by a tool it started."""

    def test_output_and_status_come_back(self):
        result = mod.run_tool(
            [sys.executable, "-c",
             "import sys; sys.stdout.write('out'); sys.stderr.write('err'); "
             "sys.exit(3)"],
            10.0)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "out")
        self.assertEqual(result.stderr, "err")
        self.assertFalse(result.timed_out)

    def test_oversized_output_is_truncated_rather_than_buffered_forever(self):
        result = mod.run_tool(
            [sys.executable, "-c",
             f"import sys; sys.stdout.write('x' * {mod.OUTPUT_LIMIT * 4})"],
            20.0)
        self.assertEqual(len(result.stdout), mod.OUTPUT_LIMIT)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.timed_out)

    def test_a_tool_that_outlives_its_deadline_is_killed(self):
        started = time.monotonic()
        result = mod.run_tool([sys.executable, "-c", "import time; time.sleep(30)"], 0.5)
        elapsed = time.monotonic() - started
        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 10.0)

    def test_the_whole_process_group_goes_down_with_it(self):
        # mount.cifs forks; killing only the process we started would leave
        # its child holding the mount point.
        script = (
            "import os, subprocess, sys, time\n"
            "child = subprocess.Popen([sys.executable, '-c',"
            " 'import time; time.sleep(30)'])\n"
            "sys.stdout.write(str(child.pid))\n"
            "sys.stdout.flush()\n"
            "time.sleep(30)\n"
        )
        result = mod.run_tool([sys.executable, "-c", script], 1.0)
        self.assertTrue(result.timed_out)
        grandchild = int(result.stdout.strip())
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
            except OSError:
                return
            time.sleep(0.05)
        self.fail("the grandchild outlived the run")

    def test_stdin_is_closed_so_a_tool_cannot_wait_on_it(self):
        result = mod.run_tool(
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
            10.0)
        self.assertEqual(result.stdout, "")
        self.assertFalse(result.timed_out)


class PureFstab(unittest.TestCase):
    """parse_fstab and render_fstab are text in, text out: no root needed."""

    OTHERS = [
        "UUID=1111  /      btrfs  noatime,subvol=@      0 0",
        "UUID=2222  /home  btrfs  noatime,subvol=@home  0 0",
    ]

    def entry(self, share="Photos", read_only=False):
        target = os.path.join("/mnt/omanas", ME.pw_name, share)
        return mod.fstab_entry(ME, "nas", share, target, "/etc/omanas/creds", read_only)

    def parse(self, lines):
        return mod.parse_fstab(lines)

    def test_untouched_when_no_block(self):
        outside, managed = self.parse(self.OTHERS)
        self.assertEqual(outside, self.OTHERS)
        self.assertEqual(managed, [])

    def test_roundtrip_preserves_foreign_lines(self):
        entry = self.entry()
        text = mod.render_fstab(self.OTHERS, [entry])
        for original in self.OTHERS:
            self.assertIn(original, text.splitlines())
        self.assertIn(mod.BEGIN, text.splitlines())
        self.assertIn(mod.END, text.splitlines())
        outside, managed = self.parse(text.splitlines())
        self.assertEqual(outside, self.OTHERS)
        self.assertEqual(managed, [entry])

    def test_removing_the_block_restores_the_original_file(self):
        text = mod.render_fstab(self.OTHERS, [self.entry()])
        outside, _ = self.parse(text.splitlines())
        self.assertEqual(mod.render_fstab(outside, []).splitlines(), self.OTHERS)

    def test_repeated_cycles_are_idempotent(self):
        entry = self.entry()
        shapes = []
        outside = self.OTHERS
        for _ in range(5):
            text = mod.render_fstab(outside, [entry])
            shapes.append(text)
            outside, _ = self.parse(text.splitlines())
        self.assertEqual(shapes[0], shapes[-1])
        self.assertEqual(shapes[-1].count("\n\n"), shapes[0].count("\n\n"))

    def test_a_begin_marker_without_an_end_is_left_alone(self):
        # Half a block means someone edited the file by hand. Rewriting from
        # a guess is how a managed block eats the line below it.
        lines = self.OTHERS + [mod.BEGIN, "//nas/x /m cifs noauto 0 0"]
        outside, managed = self.parse(lines)
        self.assertEqual(managed, [])
        self.assertIn(mod.BEGIN, outside)

    def test_an_empty_fstab(self):
        self.assertEqual(self.parse([]), ([], []))

    def test_comments_and_blank_lines_outside_the_block_survive(self):
        original = ["# /etc/fstab: static file system information", "",
                    *self.OTHERS, "", "# scratch", "tmpfs /tmp tmpfs defaults 0 0"]
        outside, _ = self.parse(original)
        lines = mod.render_fstab(outside, [self.entry()]).splitlines()
        for line in original:
            if line.strip():
                self.assertIn(line, lines)

    def test_the_text_always_ends_in_exactly_one_newline(self):
        text = mod.render_fstab(self.OTHERS, [])
        self.assertTrue(text.endswith("\n"))
        self.assertFalse(text.endswith("\n\n"))

    def test_a_second_share_joins_the_same_block(self):
        first, second = self.entry("Photos"), self.entry("Backups")
        lines = mod.render_fstab(self.OTHERS, [first, second]).splitlines()
        self.assertEqual(lines.count(mod.BEGIN), 1)
        _, managed = self.parse(lines)
        self.assertEqual(managed, [first, second])

    def test_re_persisting_a_share_replaces_its_entry(self):
        target = os.path.join("/mnt/omanas", ME.pw_name, "Photos")
        old, new = self.entry(), self.entry(read_only=True)
        _, managed = self.parse(mod.render_fstab(self.OTHERS, [old]).splitlines())
        managed = [line for line in managed if mod.entry_target(line) != target] + [new]
        _, managed = self.parse(mod.render_fstab(self.OTHERS, managed).splitlines())
        self.assertEqual(managed, [new])

    def test_forget_after_persist_leaves_no_residue(self):
        target = os.path.join("/mnt/omanas", ME.pw_name, "Time Machine")
        entry = self.entry("Time Machine")
        _, managed = self.parse(mod.render_fstab(self.OTHERS, [entry]).splitlines())
        # The space-escaped entry must still be findable by its real path.
        kept = [line for line in managed if mod.entry_target(line) != target]
        self.assertEqual(kept, [])
        self.assertEqual(mod.render_fstab(self.OTHERS, kept).splitlines(), self.OTHERS)


class Persistence(Sandbox, unittest.TestCase):
    """Whether a managed entry still names a mount point.

    It decides whether the directory may be taken back after an unmount.
    /mnt/omanas/<user> is root-owned and 0755, so a user who lost the share
    directory could not recreate it, and the noauto,user entry that was the
    whole point of persisting would name a path that no longer exists.
    """

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.root, "fstab")
        self.swap("FSTAB", self.path)
        self.target = os.path.join(mod.MOUNT_BASE, ME.pw_name, "Time Machine")
        self.entry = mod.fstab_entry(ME, "nas", "Time Machine", self.target,
                                     "/etc/omanas/creds", False)

    def write(self, *lines):
        with open(self.path, "w") as stream:
            stream.write("".join(line + "\n" for line in lines))

    def test_a_managed_entry_is_found_by_the_path_it_names(self):
        # The entry escapes the space; the lookup asks about the real path.
        self.write(*PureFstab.OTHERS, mod.BEGIN, self.entry, mod.END)
        self.assertTrue(mod.is_persisted(self.target))

    def test_another_share_is_not_this_one(self):
        self.write(mod.BEGIN, self.entry, mod.END)
        other = os.path.join(mod.MOUNT_BASE, ME.pw_name, "Photos")
        self.assertFalse(mod.is_persisted(other))

    def test_a_line_outside_the_managed_block_does_not_count(self):
        # Lines the user wrote by hand are never read as ours anywhere else
        # in this file, and they are not read as ours here either.
        self.write(*PureFstab.OTHERS, self.entry)
        self.assertFalse(mod.is_persisted(self.target))

    def test_a_missing_fstab_is_answered_rather_than_refused(self):
        # An unmount on a machine with no fstab entry at all must still work.
        self.assertFalse(os.path.exists(self.path))
        with quiet() as out:
            self.assertFalse(mod.is_persisted(self.target))
        # And it says nothing on the way: a refusal printed here would be
        # read by the panel as the answer to the command it asked for.
        self.assertEqual(out.getvalue(), "")

    @unittest.skipIf(os.geteuid() == 0, "root can read a 0000 file")
    def test_an_unreadable_fstab_is_answered_rather_than_refused(self):
        self.write(mod.BEGIN, self.entry, mod.END)
        os.chmod(self.path, 0o000)
        self.addCleanup(os.chmod, self.path, 0o644)
        with quiet() as out:
            self.assertFalse(mod.is_persisted(self.target))
        self.assertEqual(out.getvalue(), "")

    def test_a_symlinked_fstab_is_not_followed(self):
        real = os.path.join(self.root, "elsewhere")
        with open(real, "w") as stream:
            stream.write("\n".join([mod.BEGIN, self.entry, mod.END]) + "\n")
        os.symlink(real, self.path)
        with quiet():
            self.assertFalse(mod.is_persisted(self.target))


@unittest.skipUnless(HAVE_FINDMNT, "findmnt is not installed")
class FstabTransaction(Sandbox, unittest.TestCase):
    """The part that touches the real file: locked, checked, atomic."""

    OTHERS = PureFstab.OTHERS

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.root, "fstab")
        self.swap("FSTAB", self.path)
        self.write("\n".join(self.OTHERS) + "\n")

    def write(self, text):
        with open(self.path, "w") as stream:
            stream.write(text)

    def read(self):
        with open(self.path) as stream:
            return stream.read()

    def entry(self, share="Photos", read_only=False):
        target = os.path.join(mod.MOUNT_BASE, ME.pw_name, share)
        return mod.fstab_entry(ME, "nas", share, target, "/etc/omanas/creds", read_only)

    def commit(self, managed):
        with mod.Fstab() as fstab:
            fstab.managed = list(managed)
            fstab.commit()

    def test_the_block_is_written_and_read_back(self):
        entry = self.entry()
        self.commit([entry])
        with mod.Fstab() as fstab:
            self.assertEqual(fstab.managed, [entry])
            self.assertEqual(fstab.outside, self.OTHERS)

    def test_foreign_lines_survive_a_cycle(self):
        self.commit([self.entry()])
        with mod.Fstab() as fstab:
            fstab.managed = []
            fstab.commit()
        self.assertEqual(self.read().splitlines(), self.OTHERS)

    def test_the_written_file_is_world_readable(self):
        # /etc/fstab is 0644 by convention and plenty of tools read it.
        self.commit([])
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o644)

    def test_the_previous_contents_are_kept_as_a_backup(self):
        before = self.read()
        self.commit([self.entry()])
        with open(self.path + ".omanas.bak") as stream:
            self.assertEqual(stream.read(), before)

    def test_a_malformed_entry_is_refused_rather_than_written(self):
        # A corrupt fstab is an unbootable machine, so the replacement has to
        # parse before it is allowed to take the real file's place.
        before = self.read()
        with quiet() as out, self.assertRaises(SystemExit):
            self.commit(["this is not an fstab line at all"])
        self.assertIn("Refusing to write fstab", refusal(out))
        self.assertEqual(self.read(), before)

    def test_an_unreachable_share_is_not_treated_as_malformed(self):
        # findmnt --verify warns about anything it cannot reach right now,
        # and exits non-zero for warnings. Treating that as failure would
        # have refused every legitimate persist, since the whole point is a
        # share that is not mounted yet.
        entry = mod.fstab_entry(ME, "nowhere.invalid", "Photos",
                                os.path.join(mod.MOUNT_BASE, ME.pw_name, "Photos"),
                                "/etc/omanas/creds", False)
        self.commit([entry])
        self.assertIn(entry, self.read().splitlines())

    def test_a_file_that_changed_underneath_us_is_not_overwritten(self):
        # Two writers, and the second one would otherwise drop whatever the
        # first one had just added.
        with quiet() as out, self.assertRaises(SystemExit):
            with mod.Fstab() as fstab:
                fstab.managed = [self.entry()]
                self.write("\n".join(self.OTHERS + ["# somebody else"]) + "\n")
                fstab.commit()
        self.assertIn("changed while omanas was editing it", refusal(out))
        self.assertIn("# somebody else", self.read().splitlines())

    def test_a_refused_commit_leaves_no_temporary_file_behind(self):
        with quiet(), self.assertRaises(SystemExit):
            self.commit(["this is not an fstab line at all"])
        leftovers = [n for n in os.listdir(self.root) if n.startswith(".omanas-fstab-")]
        self.assertEqual(leftovers, [])

    def test_the_lock_is_released_at_the_end_of_the_transaction(self):
        # Two transactions in a row must not deadlock the second one.
        self.commit([self.entry()])
        self.commit([])
        self.assertEqual(self.read().splitlines(), self.OTHERS)

    def test_a_symlinked_fstab_is_refused(self):
        real = os.path.join(self.root, "elsewhere")
        with open(real, "w") as stream:
            stream.write("\n".join(self.OTHERS) + "\n")
        os.remove(self.path)
        os.symlink(real, self.path)
        with quiet(), self.assertRaises(SystemExit):
            self.commit([self.entry()])

    def test_an_absurdly_large_fstab_is_refused(self):
        self.write("# padding\n" * ((mod.FSTAB_LIMIT // 10) + 2))
        with quiet() as out, self.assertRaises(SystemExit):
            self.commit([])
        self.assertIn("larger than", refusal(out))


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
    TARGET = os.path.join("/mnt/omanas", ME.pw_name, "Photos")
    CREDENTIALS = "/etc/omanas/ben.Photos.deadbeef"

    def entry(self, read_only=False, share="Photos"):
        return mod.fstab_entry(ME, "nas.local", share, self.TARGET,
                               self.CREDENTIALS, read_only)

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

    def test_the_credentials_path_lives_outside_the_home_directory(self):
        # It used to sit in ~/.config/omanas, where the caller decided what
        # that name meant by the time root opened it.
        self.assertNotIn(ME.pw_dir, self.entry())

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

    def test_share_with_spaces_is_escaped(self):
        target = os.path.join("/mnt/omanas", ME.pw_name, "Time Machine")
        entry = mod.fstab_entry(ME, "nas", "Time Machine", target,
                                self.CREDENTIALS, False)
        self.assertIn("Time\\040Machine", entry)
        self.assertNotIn("Time Machine", entry)
        self.assertEqual(len(entry.split()), 6)

    def test_a_real_credentials_name_never_splits_the_options_field(self):
        name = mod.credentials_name(ME, "Time Machine")
        target = os.path.join("/mnt/omanas", ME.pw_name, "Time Machine")
        entry = mod.fstab_entry(ME, "nas", "Time Machine", target,
                                os.path.join("/etc/omanas", name), False)
        self.assertEqual(len(entry.split()), 6)

    def test_entry_target_reads_the_mountpoint_back(self):
        self.assertEqual(mod.entry_target(self.entry()), self.TARGET)

    def test_entry_target_undoes_the_escaping(self):
        target = os.path.join("/mnt/omanas", ME.pw_name, "Time Machine")
        entry = mod.fstab_entry(ME, "nas.local", "Time Machine", target,
                                self.CREDENTIALS, False)
        # Matching by the raw path missed every share with a space in it, so
        # 'forget' silently did nothing for shares like this one.
        self.assertEqual(mod.entry_target(entry), target)

    def test_entry_target_tolerates_a_line_with_no_mountpoint(self):
        self.assertEqual(mod.entry_target(""), "")
        self.assertEqual(mod.entry_target("//nas/Photos"), "")


class MountChecks(Sandbox, unittest.TestCase):
    """cmd_mount's refusals, up to but not including the mount itself."""

    def setUp(self):
        super().setUp()
        os.environ["PKEXEC_UID"] = str(os.getuid())
        self.addCleanup(os.environ.pop, "PKEXEC_UID", None)

    def args(self, share="Photos"):
        return argparse.Namespace(host="nas", share=share, account="ben",
                                  read_only=False)

    def test_an_occupied_mount_point_is_refused(self):
        target = os.path.join(mod.MOUNT_BASE, ME.pw_name, "Photos")
        self.mountinfo(f"41 28 0:38 / {target} rw shared:1 - cifs //nas/Photos rw")
        with quiet() as out, self.assertRaises(SystemExit):
            mod.cmd_mount(self.args())
        self.assertIn("Already mounted", refusal(out))

    def test_a_non_empty_mount_point_is_refused(self):
        self.mountinfo()
        point = mod.mountpoint_for(ME, "Photos")
        self.addCleanup(point.close)
        with open(os.path.join(point.path, "something"), "w"):
            pass
        with quiet() as out, self.assertRaises(SystemExit):
            mod.cmd_mount(self.args())
        self.assertIn("not empty", refusal(out))

    def test_a_share_name_is_refused_before_anything_is_created(self):
        self.mountinfo()
        with quiet() as out, self.assertRaises(SystemExit):
            mod.cmd_mount(self.args(share="Photos,ro,uid=0"))
        self.assertIn("share", refusal(out).lower())
        self.assertFalse(os.path.exists(mod.MOUNT_BASE))

    def test_unmounting_something_that_is_not_mounted_is_refused(self):
        self.mountinfo()
        with quiet() as out, self.assertRaises(SystemExit):
            mod.cmd_unmount(argparse.Namespace(share="Photos"))
        self.assertIn("Not mounted", refusal(out))


class StubbedMount(Sandbox, unittest.TestCase):
    """cmd_mount with mount and umount stubbed, so the rest can be driven.

    The kernel is the only authority on where a share ended up, so the stub
    writes the mountinfo the real mount would have caused -- or does not, to
    play the mount that reports success and delivers nothing.
    """

    def setUp(self):
        super().setUp()
        os.environ["PKEXEC_UID"] = str(os.getuid())
        self.addCleanup(os.environ.pop, "PKEXEC_UID", None)
        self.tools = os.path.join(self.root, "tools")
        os.mkdir(self.tools)
        self.swap("TOOL_DIRS", (self.tools,))
        self.argv = os.path.join(self.root, "argv")
        self.umounts = os.path.join(self.root, "umounts")
        self.table = self.mountinfo()
        # An fstab of its own: whether the share is persisted is what decides
        # the fate of the mount point, and that must not depend on whatever
        # the machine running the suite happens to have in /etc/fstab.
        self.fstab = os.path.join(self.root, "fstab")
        with open(self.fstab, "w") as stream:
            stream.write("UUID=1111  /  btrfs  defaults  0 0\n")
        self.swap("FSTAB", self.fstab)
        self.target = os.path.join(mod.MOUNT_BASE, ME.pw_name, "Time Machine")
        self.entry = ("41 28 0:38 / " + self.target.replace(" ", "\\040")
                      + " rw shared:1 - cifs //nas/Time\\040Machine rw")
        self.stub("umount", f'echo "$@" >> {self.umounts}\n: > {self.table}\nexit 0\n')

    def stub(self, name, body):
        path = os.path.join(self.tools, name)
        with open(path, "w") as stream:
            stream.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)

    def stub_mount(self, produces=None):
        lines = os.path.join(self.root, "produced")
        with open(lines, "w") as stream:
            stream.write((produces + "\n") if produces else "")
        self.stub("mount",
                  f'printf "%s\\n" "$@" > {self.argv}\ncat {lines} > {self.table}\nexit 0\n')

    def mount(self, password="hunter2\n"):
        args = argparse.Namespace(host="nas", share="Time Machine", account="ben",
                                  read_only=False)
        with quiet() as out:
            stdin = sys.stdin
            sys.stdin = io.StringIO(password)
            try:
                mod.cmd_mount(args)
            finally:
                sys.stdin = stdin
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def test_a_successful_mount_reports_the_derived_path(self):
        self.stub_mount(self.entry)
        answer = self.mount()
        self.assertTrue(answer["ok"])
        self.assertEqual(answer["mountpoint"], self.target)

    def test_the_password_never_reaches_the_command_line(self):
        self.stub_mount(self.entry)
        self.mount()
        argv = open(self.argv).read()
        self.assertNotIn("hunter2", argv)
        self.assertIn("credentials=", argv)
        self.assertIn(mod.RUNTIME_DIR, argv)

    def test_the_credentials_file_is_gone_afterwards(self):
        # It lives on tmpfs and only until mount.cifs has read it.
        self.stub_mount(self.entry)
        self.mount()
        self.assertEqual(os.listdir(mod.RUNTIME_DIR), [])
        self.assertEqual(os.stat(mod.RUNTIME_DIR).st_mode & 0o777, 0o700)

    def test_a_mount_that_reports_success_and_delivers_nothing_is_refused(self):
        # mount exiting 0 is not evidence; the mount table is.
        self.stub_mount(None)
        with self.assertRaises(SystemExit):
            self.mount()
        self.assertFalse(os.path.exists(self.target))

    def test_a_share_that_landed_elsewhere_is_unmounted_again(self):
        self.stub_mount("41 28 0:38 / /etc rw shared:1 - cifs //nas/Time\\040Machine rw")
        with quiet(), self.assertRaises(SystemExit):
            self.mount()
        self.assertEqual(open(self.umounts).read().split(), ["/etc"])

    def persist_entry(self):
        """Put a managed fstab entry naming this share's mount point in place."""
        line = mod.fstab_entry(ME, "nas", "Time Machine", self.target,
                               "/etc/omanas/creds", False)
        with open(self.fstab, "a") as stream:
            stream.write("\n".join(["", mod.BEGIN, line, mod.END]) + "\n")

    def unmount(self):
        with quiet() as out:
            mod.cmd_unmount(argparse.Namespace(share="Time Machine"))
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def test_unmount_removes_the_directory_it_made(self):
        self.stub_mount(self.entry)
        self.mount()
        self.unmount()
        self.assertFalse(os.path.exists(self.target))

    def test_unmount_keeps_a_directory_a_managed_entry_still_names(self):
        # Removing it would leave the noauto,user entry naming nothing, and
        # the root-owned parent means the user could not put it back: the
        # share would be unmountable until someone with root intervened.
        self.persist_entry()
        self.stub_mount(self.entry)
        self.mount()
        self.assertTrue(self.unmount()["ok"])
        self.assertTrue(os.path.isdir(self.target))

    def test_a_failed_mount_gives_the_directory_back(self):
        self.stub("mount", "exit 32\n")
        with quiet(), self.assertRaises(SystemExit):
            self.mount()
        self.assertFalse(os.path.exists(self.target))

    def test_a_failed_mount_keeps_a_directory_a_managed_entry_still_names(self):
        self.persist_entry()
        self.stub("mount", "exit 32\n")
        with quiet(), self.assertRaises(SystemExit):
            self.mount()
        self.assertTrue(os.path.isdir(self.target))


@unittest.skipUnless(HAVE_FINDMNT, "findmnt is not installed")
class PersistAndForget(Sandbox, unittest.TestCase):
    """The whole persist path, from stdin to the managed block and back."""

    OTHERS = PureFstab.OTHERS

    def setUp(self):
        super().setUp()
        os.environ["PKEXEC_UID"] = str(os.getuid())
        self.addCleanup(os.environ.pop, "PKEXEC_UID", None)
        self.path = os.path.join(self.root, "fstab")
        self.swap("FSTAB", self.path)
        with open(self.path, "w") as stream:
            stream.write("\n".join(self.OTHERS) + "\n")

    def persist(self, share="Time Machine", password="hunter2\n"):
        args = argparse.Namespace(host="nas.local", share=share, account="ben",
                                  read_only=False)
        with quiet() as out:
            stdin = sys.stdin
            sys.stdin = io.StringIO(password)
            try:
                mod.cmd_persist(args)
            finally:
                sys.stdin = stdin
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def forget(self, share="Time Machine"):
        with quiet() as out:
            mod.cmd_forget(argparse.Namespace(share=share))
        return json.loads(out.getvalue().strip().splitlines()[-1])

    def test_the_entry_names_the_derived_mount_point(self):
        answer = self.persist()
        expected = os.path.join(mod.MOUNT_BASE, ME.pw_name, "Time Machine")
        self.assertTrue(answer["ok"])
        self.assertEqual(answer["mountpoint"], expected)
        self.assertTrue(os.path.isdir(expected))
        with mod.Fstab() as fstab:
            self.assertEqual(len(fstab.managed), 1)
            self.assertEqual(mod.entry_target(fstab.managed[0]), expected)
            self.assertEqual(len(fstab.managed[0].split()), 6)

    def test_the_credentials_land_in_the_state_directory(self):
        self.persist()
        name = mod.credentials_name(ME, "Time Machine")
        path = os.path.join(mod.STATE_DIR, name)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(mod.STATE_DIR).st_mode & 0o777, 0o700)
        with open(path) as stream:
            self.assertIn("password=hunter2", stream.read())

    def test_persisting_twice_leaves_one_entry(self):
        self.persist()
        self.persist()
        with mod.Fstab() as fstab:
            self.assertEqual(len(fstab.managed), 1)
            self.assertEqual(fstab.outside, self.OTHERS)

    def test_forget_removes_the_entry_and_the_credentials(self):
        self.persist()
        path = os.path.join(mod.STATE_DIR, mod.credentials_name(ME, "Time Machine"))
        self.assertTrue(self.forget()["changed"])
        self.assertFalse(os.path.exists(path))
        with open(self.path) as stream:
            self.assertEqual(stream.read().splitlines(), self.OTHERS)

    def test_forgetting_something_unknown_changes_nothing(self):
        answer = self.forget("Photos")
        self.assertTrue(answer["ok"])
        self.assertFalse(answer["changed"])

    def stored(self):
        """What the state directory holds, apart from the fstab lock."""
        return sorted(n for n in os.listdir(mod.STATE_DIR) if n != mod.LOCK_NAME)

    def test_a_successful_persist_leaves_exactly_one_credentials_file(self):
        self.persist()
        self.persist()
        self.assertEqual(self.stored(), [mod.credentials_name(ME, "Time Machine")])

    def test_a_persist_that_does_not_commit_leaves_no_password_behind(self):
        # The credentials file is root-only readable, so an orphan is
        # untidiness rather than exposure -- but nothing would ever come back
        # to clean it up, and it holds the user's SMB password.
        with open(self.path, "a") as stream:
            stream.write("this is not an fstab line at all\n")
        with self.assertRaises(SystemExit):
            self.persist()
        with open(self.path) as stream:
            self.assertNotIn(mod.BEGIN, stream.read())
        self.assertEqual(self.stored(), [])

    def test_a_failed_re_persist_keeps_the_file_the_committed_entry_uses(self):
        # The entry from the first persist is still in /etc/fstab -- this
        # transaction is the one that failed -- so the file it names has to
        # stay. Rolling it back would turn a mount that works today into one
        # that fails on a credentials file that is not there.
        self.persist()
        name = mod.credentials_name(ME, "Time Machine")
        with open(self.path, "a") as stream:
            stream.write("this is not an fstab line at all\n")
        with self.assertRaises(SystemExit):
            self.persist(password="hunter3\n")
        self.assertEqual(self.stored(), [name])
        with mod.Fstab() as fstab:
            self.assertEqual(len(fstab.managed), 1)

    def test_no_password_on_stdin_is_refused(self):
        with self.assertRaises(SystemExit):
            self.persist(password="\n")
        with open(self.path) as stream:
            self.assertEqual(stream.read().splitlines(), self.OTHERS)


class CallerIdentity(unittest.TestCase):
    def test_refuses_without_pkexec_uid(self):
        env = {k: v for k, v in os.environ.items() if k != "PKEXEC_UID"}
        result = subprocess.run(
            [sys.executable, HELPER, "unmount", "--share", "Photos"],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PKEXEC_UID", json.loads(result.stdout)["error"])

    def test_refuses_bogus_pkexec_uid(self):
        env = dict(os.environ, PKEXEC_UID="999999")
        result = subprocess.run(
            [sys.executable, HELPER, "unmount", "--share", "Photos"],
            capture_output=True, text=True, env=env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("real user", json.loads(result.stdout)["error"])


class CommandLine(unittest.TestCase):
    """The caller cannot name a path, because there is no flag for one."""

    def parse(self, argv):
        with contextlib.redirect_stderr(io.StringIO()):
            return mod.build_parser().parse_args(argv)

    def test_no_subcommand_accepts_a_mountpoint(self):
        for argv in [
            ["mount", "--host", "nas", "--share", "S", "--account", "a",
             "--mountpoint", "/etc"],
            ["unmount", "--share", "S", "--mountpoint", "/etc"],
            ["persist", "--host", "nas", "--share", "S", "--account", "a",
             "--mountpoint", "/etc"],
            ["forget", "--share", "S", "--mountpoint", "/etc"],
            ["list", "--mountpoint", "/etc"],
        ]:
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                self.parse(argv)

    def test_the_share_is_what_every_subcommand_takes(self):
        for argv in [
            ["mount", "--host", "nas", "--share", "Photos", "--account", "ben"],
            ["unmount", "--share", "Photos"],
            ["persist", "--host", "nas", "--share", "Photos", "--account", "ben"],
            ["forget", "--share", "Photos"],
        ]:
            with self.subTest(argv=argv):
                self.assertEqual(self.parse(argv).share, "Photos")


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
        result = self.run_helper(["unmount", "--share", "Photos"], uid=os.getuid())
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
             "--account", "ben"],
            uid=os.getuid(), stdin="hunter2\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("share", json.loads(result.stdout)["error"].lower())

    def test_a_mountpoint_argument_is_rejected_outright(self):
        result = self.run_helper(
            ["mount", "--host", "nas", "--share", "Photos", "--account", "ben",
             "--mountpoint", "/etc"],
            uid=os.getuid(), stdin="hunter2\n")
        self.assertNotEqual(result.returncode, 0)

    def test_the_request_is_refused_before_the_password_is_read(self):
        # Refusing early means a crafted request never gets to hold a
        # credential in this process at all.
        result = self.run_helper(
            ["mount", "--host", "nas,uid=0", "--share", "Photos",
             "--account", "ben"],
            uid=os.getuid(), stdin="hunter2\n")
        self.assertIn("host", json.loads(result.stdout)["error"].lower())

    def test_the_executable_bit_is_set(self):
        # pkexec runs it directly.
        self.assertTrue(os.stat(HELPER).st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
