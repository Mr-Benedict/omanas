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
    def test_a_share_lands_under_the_mount_root(self):
        self.assertEqual(mod.mount_target({}, "/home/me/nas", "Photos"),
                         "/home/me/nas/Photos")

    def test_a_tilde_is_expanded(self):
        target = mod.mount_target({}, "~/mnt/nas", "Photos")
        self.assertTrue(target.startswith(os.path.expanduser("~")))
        self.assertTrue(target.endswith("/mnt/nas/Photos"))

    def test_an_empty_root_falls_back_to_the_documented_default(self):
        self.assertEqual(mod.mount_target({}, "", "Photos"),
                         os.path.expanduser("~/mnt/nas/Photos"))

    def test_a_share_with_a_space_is_not_mangled(self):
        self.assertEqual(mod.mount_target({}, "/mnt", "Time Machine"),
                         "/mnt/Time Machine")


class Privileged(unittest.TestCase):
    """The pkexec hand-off, with subprocess.run replaced by a recorder."""

    def setUp(self):
        self.calls = []
        self.result = subprocess.CompletedProcess([], 0, stdout='{"ok": true}\n', stderr="")
        self.addCleanup(setattr, mod.subprocess, "run", mod.subprocess.run)
        mod.subprocess.run = self._run
        self.addCleanup(setattr, mod, "MOUNT_HELPER", mod.MOUNT_HELPER)

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
        self.assertEqual(self.calls[0]["argv"][0], "pkexec")
        self.assertEqual(self.calls[0]["argv"][1], mod.MOUNT_HELPER)

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
