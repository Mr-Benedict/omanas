"""Tests for the command surface and the chain that reaches the root helper.

The panel's only way to do anything is to run this script and read a line of
JSON, so the contract worth pinning down is that every command answers with
JSON on both the success and the failure path -- a command that raises and
prints a traceback looks to QML exactly like a command that did nothing.

The other thing tested here is the hand-off to pkexec, where the SMB password
crosses from the keyring to a root process. It goes on stdin. An argv element
would be readable out of /proc by every user on the machine for as long as
the mount takes.
"""

import json
import os
import pwd
import shutil
import stat
import subprocess
import tempfile
import unittest

from helpers import HELPER, omanas, quiet

mod = omanas()


class Parser(unittest.TestCase):
    """Every documented invocation must parse, and reach a handler."""

    PARSER = mod.build_parser()

    INVOCATIONS = [
        ["configure", "--host", "nas.local", "--user", "ben"],
        ["configure", "--host", "nas.local", "--user", "ben", "--no-https", "--port", "5000"],
        ["configure", "--host", "nas.local", "--user", "ben", "--accept-new-cert"],
        ["login"],
        ["login", "--otp", "123456", "--force"],
        ["logout"],
        ["connect", "--host", "nas.local", "--user", "ben"],
        ["connect", "--host", "nas.local", "--user", "ben", "--otp", "123456"],
        ["connect", "--host", "nas.local", "--user", "ben", "--no-https", "--accept-new-cert"],
        ["status"],
        ["status", "--logs", "25"],
        ["utilisation"],
        ["diagnostics"],
        ["mount", "--share", "Photos"],
        ["mount", "--share", "Photos", "--persist", "--read-only"],
        ["mount", "--share", "Photos", "--mount-root", "/home/me/nas"],
        ["unmount", "--share", "Photos"],
        ["forget", "--share", "Photos"],
        ["unlock", "--share", "Backups"],
        ["lock", "--share", "Backups"],
        ["probe"],
        ["probe", "--call", "--raw", "--otp", "123456"],
    ]

    def test_every_invocation_parses_and_dispatches(self):
        for argv in self.INVOCATIONS:
            with self.subTest(argv=argv):
                args = self.PARSER.parse_args(argv)
                self.assertTrue(callable(getattr(args, "func", None)))

    def test_a_subcommand_is_required(self):
        with self.assertRaises(SystemExit):
            self.PARSER.parse_args([])

    def test_an_unknown_subcommand_is_refused(self):
        with self.assertRaises(SystemExit):
            self.PARSER.parse_args(["definitely-not-a-command"])

    def test_share_is_required_wherever_one_is_meant(self):
        for command in ["mount", "unmount", "forget", "unlock", "lock"]:
            with self.subTest(command=command), self.assertRaises(SystemExit):
                self.PARSER.parse_args([command])

    def test_the_default_mount_root_matches_the_manifest(self):
        self.assertEqual(self.PARSER.parse_args(["mount", "--share", "x"]).mount_root,
                         "~/mnt/nas")


class Config(unittest.TestCase):
    def setUp(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(self._clean, directory)
        self.addCleanup(setattr, mod, "CONFIG_PATH", mod.CONFIG_PATH)
        self.addCleanup(setattr, mod, "CONFIG_DIR", mod.CONFIG_DIR)
        mod.CONFIG_DIR = directory
        mod.CONFIG_PATH = os.path.join(directory, "config.json")

    def _clean(self, directory):
        for entry in os.listdir(directory):
            os.remove(os.path.join(directory, entry))
        os.rmdir(directory)

    def test_round_trip(self):
        mod.save_config({"host": "nas.local", "username": "ben", "port": 5001})
        self.assertEqual(mod.load_config()["host"], "nas.local")

    def test_a_missing_file_is_not_an_error(self):
        # First run. The panel shows its setup form rather than a failure.
        self.assertEqual(mod.load_config(), {})

    def test_the_file_is_not_world_readable(self):
        # No secret lives here, but the account name and the pinned
        # fingerprint do, and 0600 costs nothing.
        mod.save_config({"host": "nas.local"})
        self.assertEqual(os.stat(mod.CONFIG_PATH).st_mode & 0o777, 0o600)

    def test_a_corrupt_file_names_itself(self):
        with open(mod.CONFIG_PATH, "w") as handle:
            handle.write("{ not json")
        with self.assertRaises(SystemExit) as caught:
            mod.load_config()
        self.assertIn(mod.CONFIG_PATH, str(caught.exception))

    def test_saving_is_atomic(self):
        # A half-written config is a plugin that cannot start. The write goes
        # to a temporary file and is renamed into place.
        mod.save_config({"host": "nas.local"})
        mod.save_config({"host": "other.local"})
        self.assertEqual(os.listdir(mod.CONFIG_DIR), ["config.json"])

    def test_the_scratch_file_is_not_a_predictable_name(self):
        # It used to be config.json.tmp, which anyone could create first.
        # Whatever mkstemp picks, nothing is left behind under either name.
        mod.save_config({"host": "nas.local"})
        self.assertFalse(os.path.exists(mod.CONFIG_PATH + ".tmp"))
        self.assertEqual(os.listdir(mod.CONFIG_DIR), ["config.json"])

    def test_a_write_that_fails_leaves_no_scratch_file(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(os.rmdir, directory)
        with self.assertRaises(TypeError):
            mod.write_private(os.path.join(directory, "config.json"), None)
        self.assertEqual(os.listdir(directory), [])

    def test_a_written_file_is_private_from_the_first_byte(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        path = os.path.join(directory, "session.json")
        mod.write_private(path, "{}")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class Keyring(unittest.TestCase):
    def test_attributes_identify_one_credential_on_one_nas(self):
        attrs = mod.secret_attrs({"host": "nas.local", "username": "ben"}, "password")
        pairs = dict(zip(attrs[::2], attrs[1::2]))
        self.assertEqual(pairs["service"], "omanas")
        self.assertEqual(pairs["host"], "nas.local")
        self.assertEqual(pairs["account"], "ben")
        self.assertEqual(pairs["kind"], "password")

    def test_the_password_and_the_device_token_are_separate_entries(self):
        config = {"host": "nas.local", "username": "ben"}
        self.assertNotEqual(mod.secret_attrs(config, "password"),
                            mod.secret_attrs(config, "device_id"))

    def test_a_config_with_nothing_in_it_still_produces_valid_attributes(self):
        # secret-tool takes attributes in pairs; a None would break the call.
        attrs = mod.secret_attrs({}, "password")
        self.assertEqual(len(attrs) % 2, 0)
        self.assertTrue(all(isinstance(value, str) for value in attrs))


class MountTargets(unittest.TestCase):
    """The mountpoint is derived, on this side and in the root helper.

    Nobody names it: the path is a chain of root-owned directories, which is
    what stops anything on it being swapped for a symlink between the helper
    checking the directory and mounting on it.
    """

    USER = pwd.getpwuid(os.getuid()).pw_name

    def test_a_share_lands_under_the_root_owned_base(self):
        self.assertEqual(mod.mount_target("Photos"),
                         f"/mnt/omanas/{self.USER}/Photos")

    def test_the_base_is_not_under_the_user_s_home(self):
        # A mountpoint the user can rename is a mountpoint the user can
        # replace between the check and the mount.
        self.assertFalse(mod.mount_target("Photos").startswith(
            os.path.expanduser("~") + os.sep))

    def test_each_account_gets_its_own_subtree(self):
        self.assertIn(f"/{self.USER}/", mod.mount_target("Photos"))

    def test_a_share_with_a_space_is_not_mangled(self):
        self.assertEqual(mod.mount_target("Time Machine"),
                         f"/mnt/omanas/{self.USER}/Time Machine")


class Tools(unittest.TestCase):
    """Every program this helper runs is named by absolute path."""

    def test_an_installed_tool_resolves_to_an_absolute_path(self):
        found = mod.tool("sh")
        self.assertIsNotNone(found)
        self.assertTrue(os.path.isabs(found))
        self.assertIn(os.path.dirname(found), mod.TOOL_DIRS)
        self.assertTrue(os.access(found, os.X_OK))

    def test_a_missing_tool_is_none_rather_than_a_bare_name(self):
        # A bare name would be handed to subprocess, which would resolve it
        # through PATH -- the thing this exists to avoid.
        self.assertIsNone(mod.tool("omanas-no-such-tool"))

    def test_path_is_never_consulted(self):
        # PATH belongs to whoever started the panel. A 'pkexec' planted
        # earlier on it would be handed the NAS password on stdin.
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        planted = os.path.join(directory, "omanas-no-such-tool")
        with open(planted, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 0\n")
        os.chmod(planted, 0o755)

        previous = os.environ.get("PATH", "")
        self.addCleanup(os.environ.__setitem__, "PATH", previous)
        os.environ["PATH"] = directory + os.pathsep + previous
        self.assertIsNone(mod.tool("omanas-no-such-tool"))


class ShortcutToTheMountRoot(unittest.TestCase):
    """mountRoot stopped being where shares live and became a link to it."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        self.real = os.path.join(mod.MOUNT_BASE, pwd.getpwuid(os.getuid()).pw_name)

    def test_a_free_path_gets_a_link_to_the_real_root(self):
        target = os.path.join(self.home, "mnt", "nas")
        mod.link_mount_root(target)
        self.assertTrue(os.path.islink(target))
        self.assertEqual(os.readlink(target), self.real)

    def test_an_existing_directory_is_left_exactly_alone(self):
        # Someone may already keep things in ~/mnt/nas. Replacing it with a
        # link would hide them.
        target = os.path.join(self.home, "mnt", "nas")
        os.makedirs(target)
        with open(os.path.join(target, "notes.txt"), "w", encoding="utf-8") as handle:
            handle.write("mine")
        mod.link_mount_root(target)
        self.assertFalse(os.path.islink(target))
        self.assertEqual(os.listdir(target), ["notes.txt"])

    def test_a_link_pointing_somewhere_else_is_not_repointed(self):
        target = os.path.join(self.home, "nas")
        os.symlink("/var/empty", target)
        mod.link_mount_root(target)
        self.assertEqual(os.readlink(target), "/var/empty")

    def test_running_it_twice_changes_nothing(self):
        target = os.path.join(self.home, "nas")
        mod.link_mount_root(target)
        mod.link_mount_root(target)
        self.assertEqual(os.readlink(target), self.real)

    def test_a_path_that_cannot_be_made_is_not_an_error(self):
        # A mount that worked must never be reported as failed because a
        # convenience symlink could not be created.
        mod.link_mount_root("/proc/omanas/nas")


class Privileged(unittest.TestCase):
    """The pkexec hand-off, with subprocess.run replaced by a recorder."""

    def setUp(self):
        self.calls = []
        self.result = subprocess.CompletedProcess([], 0, stdout='{"ok": true}\n', stderr="")
        self.addCleanup(setattr, mod.subprocess, "run", mod.subprocess.run)
        mod.subprocess.run = self._run
        self.addCleanup(setattr, mod, "MOUNT_HELPER", mod.MOUNT_HELPER)
        # pkexec is resolved rather than looked up on PATH, and a machine
        # without it would otherwise never reach subprocess at all.
        self.addCleanup(setattr, mod, "tool", mod.tool)
        mod.tool = lambda name: "/usr/bin/" + name

    def _run(self, argv, **kwargs):
        self.calls.append({"argv": argv, **kwargs})
        return self.result

    def test_the_password_goes_on_stdin_and_not_into_argv(self):
        # /proc/<pid>/cmdline is world-readable. A password there is a
        # password any local user can read for the life of the mount.
        mod.run_privileged(["mount", "--share", "Photos"], "hunter2")
        call = self.calls[0]
        self.assertNotIn("hunter2", " ".join(call["argv"]))
        self.assertEqual(call["input"], "hunter2\n")

    def test_it_goes_through_pkexec_rather_than_running_as_root_directly(self):
        mod.run_privileged(["unmount"], None)
        self.assertEqual(self.calls[0]["argv"][0], "/usr/bin/pkexec")
        self.assertEqual(self.calls[0]["argv"][1], mod.MOUNT_HELPER)

    def test_pkexec_is_named_by_absolute_path(self):
        mod.run_privileged(["unmount"], None)
        self.assertTrue(os.path.isabs(self.calls[0]["argv"][0]))

    def test_the_call_carries_a_deadline(self):
        # Nothing can cancel a helper the panel is already waiting on.
        mod.run_privileged(["unmount"], None)
        self.assertGreater(self.calls[0]["timeout"], 0)

    def test_a_helper_that_never_answers_becomes_an_error_not_a_hang(self):
        def hanging(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))

        mod.subprocess.run = hanging
        answer = mod.run_privileged(["mount"], "p")
        self.assertFalse(answer["ok"])
        self.assertTrue(answer["error"])

    def test_a_flood_of_stderr_is_truncated_before_it_is_reported(self):
        # The panel renders result.error in a label; a megabyte of kernel
        # noise there is neither readable nor free.
        self.result = subprocess.CompletedProcess([], 32, "", "x" * 1000000)
        self.assertLessEqual(len(mod.run_privileged(["mount"], "p")["error"]),
                             mod.MAX_OUTPUT_CHARS + 1)

    def test_a_call_with_no_password_sends_an_empty_stdin(self):
        # unmount and forget need no credential; the helper still reads a
        # line, so it must get one rather than block.
        mod.run_privileged(["unmount"], None)
        self.assertEqual(self.calls[0]["input"], "")

    def test_the_helper_s_json_is_passed_straight_through(self):
        self.result = subprocess.CompletedProcess([], 0, '{"ok": true, "mountpoint": "/m"}', "")
        self.assertEqual(mod.run_privileged(["mount"], "p"),
                         {"ok": True, "mountpoint": "/m"})

    def test_only_the_last_line_is_read(self):
        # mount.cifs writes warnings to stdout; the helper's answer is last.
        self.result = subprocess.CompletedProcess(
            [], 0, 'CIFS: some kernel warning\n{"ok": true}\n', "")
        self.assertEqual(mod.run_privileged(["mount"], "p"), {"ok": True})

    def test_a_dismissed_polkit_dialog_is_not_reported_as_a_failure(self):
        # 126 is polkit's own code for "the user pressed Cancel". The panel
        # shows nothing rather than an error, because nothing went wrong.
        self.result = subprocess.CompletedProcess([], 126, "", "")
        answer = mod.run_privileged(["mount"], "p")
        self.assertTrue(answer["cancelled"])
        self.assertFalse(answer["ok"])

    def test_an_unrunnable_helper_says_so(self):
        self.result = subprocess.CompletedProcess([], 127, "", "")
        self.assertIn("pkexec", mod.run_privileged(["mount"], "p")["error"])

    def test_a_failure_with_no_json_falls_back_to_the_last_stderr_line(self):
        self.result = subprocess.CompletedProcess(
            [], 32, "", "mount error(13): Permission denied\n")
        self.assertIn("Permission denied", mod.run_privileged(["mount"], "p")["error"])

    def test_a_silent_failure_still_produces_an_error_string(self):
        # The panel renders result.error; an absent key would render "undefined".
        self.result = subprocess.CompletedProcess([], 1, "", "")
        answer = mod.run_privileged(["mount"], "p")
        self.assertFalse(answer["ok"])
        self.assertTrue(answer["error"])

    def test_a_missing_helper_is_reported_before_pkexec_is_asked(self):
        # Otherwise the user authenticates and only then finds out.
        mod.MOUNT_HELPER = "/nonexistent/omanas-mount"
        answer = mod.run_privileged(["mount"], "p")
        self.assertFalse(answer["ok"])
        self.assertEqual(self.calls, [])

    def test_pkexec_not_installed_is_named(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError("pkexec")
        mod.subprocess.run = missing
        self.assertIn("pkexec", mod.run_privileged(["mount"], "p")["error"])

    def test_an_unresolvable_pkexec_is_reported_before_anything_is_run(self):
        mod.tool = lambda name: None
        answer = mod.run_privileged(["mount"], "p")
        self.assertIn("pkexec", answer["error"])
        self.assertEqual(self.calls, [])


class BoundedResponses(unittest.TestCase):
    """The NAS is trusted to be the NAS, not to be well behaved."""

    class Endless:
        """Answers with exactly as much as it is asked for, forever."""

        status = 200

        def read(self, limit):
            return b"x" * limit

    class Sized:
        status = 200

        def __init__(self, payload):
            self.payload = payload.encode("utf-8")

        def read(self, limit):
            return self.payload[:limit]

    class Connection:
        def __init__(self, response):
            self.response = response

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return self.response

        def close(self):
            pass

    def dsm(self, response):
        client = mod.Dsm({"host": "nas.local", "username": "ben", "port": 5001})
        client._conn = self.Connection(response)
        return client

    def test_an_oversized_body_is_refused_rather_than_swallowed(self):
        # Reading whatever arrives lets whatever is on that port decide how
        # much memory this process allocates.
        with self.assertRaises(mod.DsmError) as caught:
            self.dsm(self.Endless())._request("query.cgi")
        self.assertIn("MiB", str(caught.exception))

    def test_the_read_is_asked_for_one_byte_past_the_limit(self):
        # Asking for exactly the limit would make a body of exactly that size
        # indistinguishable from the first slice of a larger one, so an
        # oversized answer would be silently truncated instead of refused.
        # The extra byte is the whole of how "too big" is detected.
        asked = []

        class Recording(self.Sized):
            def read(self, limit):
                asked.append(limit)
                return super().read(limit)

        body = json.dumps({"success": True, "data": {}})
        self.dsm(Recording(body))._request("query.cgi")
        self.assertEqual(asked, [mod.MAX_RESPONSE_BYTES + 1])

    def test_an_ordinary_answer_still_arrives_whole(self):
        body = json.dumps({"success": True, "data": {"model": "DS923+"}})
        self.assertEqual(self.dsm(self.Sized(body))._request("query.cgi"),
                         json.loads(body))


class Capabilities(unittest.TestCase):
    """The panel greys out what a NAS cannot serve, so this drives the UI."""

    class FakeDsm:
        def __init__(self, apis):
            self._apis = apis

        def discover(self):
            return self._apis

    def test_a_full_dsm_offers_everything(self):
        caps = mod.capabilities(self.FakeDsm({
            "SYNO.Core.System": {}, "SYNO.Core.System.Utilization": {},
            "SYNO.Storage.CGI.Storage": {}, "SYNO.Core.Share": {},
            "SYNO.Core.Share.Crypto": {}, "SYNO.Core.SystemLog": {},
        }))
        self.assertTrue(caps["system"])
        self.assertEqual(caps["logs"], "SYNO.Core.SystemLog")
        self.assertEqual(caps["storage"], "SYNO.Storage.CGI.Storage")
        self.assertEqual(caps["crypto"], "SYNO.Core.Share.Crypto")

    def test_the_preferred_candidate_wins_when_several_are_present(self):
        caps = mod.capabilities(self.FakeDsm({
            "SYNO.Core.SystemLog": {}, "SYNO.Core.Log": {},
            "SYNO.LogCenter.Log": {},
        }))
        self.assertEqual(caps["logs"], "SYNO.Core.SystemLog")

    def test_an_older_dsm_falls_back(self):
        caps = mod.capabilities(self.FakeDsm({"SYNO.Core.Storage.Volume": {},
                                              "SYNO.Core.Log": {}}))
        self.assertEqual(caps["storage"], "SYNO.Core.Storage.Volume")
        self.assertEqual(caps["logs"], "SYNO.Core.Log")

    def test_a_bare_dsm_reports_nothing_rather_than_raising(self):
        caps = mod.capabilities(self.FakeDsm({}))
        self.assertFalse(caps["system"])
        self.assertEqual(caps["logs"], "")
        self.assertEqual(caps["crypto"], "")

    def test_every_capability_is_reported_even_when_absent(self):
        # The panel reads each key; a missing one is undefined in QML, which
        # is truthy enough to render a control that cannot work.
        caps = mod.capabilities(self.FakeDsm({}))
        self.assertEqual(set(caps), {"system", "utilisation", "storage",
                                     "shares", "crypto", "logs"})


class AccessibleShares(unittest.TestCase):
    """Lock state is inferred from this, so 'cannot say' must not become a guess."""

    class FakeDsm:
        def __init__(self, answer):
            self.answer = answer

        def call(self, *args, **kwargs):
            # SystemExit is a BaseException, not an Exception; catching the
            # narrower type here would have let an unreachable NAS through.
            if isinstance(self.answer, BaseException):
                raise self.answer
            return self.answer

    def test_a_list_becomes_a_set_of_names(self):
        found = mod.accessible_shares(self.FakeDsm(
            {"shares": [{"name": "Photos"}, {"name": "Backups"}]}))
        self.assertEqual(found, {"Photos", "Backups"})

    def test_a_refused_call_is_unknown_not_empty(self):
        # An empty set would mark every encrypted share as locked. A non-admin
        # account is refused here routinely.
        self.assertIsNone(mod.accessible_shares(self.FakeDsm(mod.DsmError(105))))

    def test_an_unreachable_nas_is_unknown_too(self):
        self.assertIsNone(mod.accessible_shares(self.FakeDsm(SystemExit("no route"))))

    def test_an_unexpected_payload_is_unknown(self):
        self.assertIsNone(mod.accessible_shares(self.FakeDsm({"shares": "nope"})))
        self.assertIsNone(mod.accessible_shares(self.FakeDsm({})))

    def test_nameless_rows_are_dropped(self):
        found = mod.accessible_shares(self.FakeDsm(
            {"shares": [{"name": "Photos"}, {}, {"name": ""}]}))
        self.assertEqual(found, {"Photos"})


class MainLoop(unittest.TestCase):
    def test_a_dsm_error_becomes_json_rather_than_a_traceback(self):
        # QML reads stdout. A traceback on stderr is indistinguishable from
        # the command having done nothing at all.
        parser_args = mod.build_parser().parse_args(["logout"])

        def raising(args):
            raise mod.DsmError(105, "SYNO.Core.System", "info")

        parser_args.func = raising
        self.addCleanup(setattr, mod, "build_parser", mod.build_parser)
        mod.build_parser = lambda: FakeParser(parser_args)

        with quiet() as out:
            code = mod.main(["logout"])
        self.assertEqual(code, 1)
        answer = json.loads(out.getvalue())
        self.assertFalse(answer["ok"])
        self.assertEqual(answer["code"], 105)

    def test_an_interrupt_uses_the_conventional_status(self):
        parser_args = mod.build_parser().parse_args(["logout"])

        def interrupted(args):
            raise KeyboardInterrupt

        parser_args.func = interrupted
        self.addCleanup(setattr, mod, "build_parser", mod.build_parser)
        mod.build_parser = lambda: FakeParser(parser_args)
        self.assertEqual(mod.main(["logout"]), 130)


class FakeParser:
    def __init__(self, args):
        self._args = args

    def parse_args(self, argv):
        return self._args


class Executable(unittest.TestCase):
    def test_the_helper_can_be_run_by_the_panel(self):
        # The panel runs bin/omanas directly, not through an interpreter.
        info = os.stat(HELPER)
        self.assertTrue(info.st_mode & stat.S_IXUSR)
        with open(HELPER, encoding="utf-8") as handle:
            self.assertTrue(handle.readline().startswith("#!"))

    def test_help_works_without_any_configuration(self):
        result = subprocess.run([HELPER, "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Synology", result.stdout)

    def test_status_on_an_unconfigured_machine_answers_rather_than_failing(self):
        # First run, before the setup form has been filled in.
        env = dict(os.environ, HOME=tempfile.mkdtemp())
        self.addCleanup(os.rmdir, env["HOME"])
        result = subprocess.run([HELPER, "status"], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"ok": False, "configured": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
