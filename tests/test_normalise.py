"""Tests for the layer that turns DSM's answers into the panel's model.

These field names came from reverse-engineered clients, so the point of every
test here is the same: when DSM says something unexpected, the panel gets a
usable value rather than an exception.
"""

import os
import tempfile
import time
import unittest

from helpers import omanas

mod = omanas()


class Scalars(unittest.TestCase):
    def test_as_number_survives_dsm_habits(self):
        self.assertEqual(mod.as_number("123456"), 123456)   # sizes are strings
        self.assertEqual(mod.as_number(42), 42)
        self.assertEqual(mod.as_number(""), 0)              # gaps are empty strings
        self.assertEqual(mod.as_number(None), 0)
        self.assertEqual(mod.as_number("not a number"), 0)
        self.assertEqual(mod.as_number(None, 5), 5)

    def test_uptime_in_either_spelling(self):
        self.assertEqual(mod.parse_uptime("90061"), 90061)
        self.assertEqual(mod.parse_uptime("12:34:56"), 12 * 3600 + 34 * 60 + 56)
        self.assertEqual(mod.parse_uptime(""), 0)
        self.assertEqual(mod.parse_uptime(None), 0)
        self.assertEqual(mod.parse_uptime("garbage"), 0)

    def test_first_key_prefers_the_spelling_present(self):
        self.assertEqual(mod.first_key({"desc": "x"}, "descr", "desc"), "x")
        self.assertEqual(mod.first_key({"descr": ""}, "descr", "desc", default="fallback"), "fallback")
        self.assertIsNone(mod.first_key({}, "a", "b"))


class System(unittest.TestCase):
    SAMPLE = {
        "model": "DS923+", "firmware_ver": "DSM 7.2.1-69057", "up_time": "251:22:19",
        "sys_temp": 41, "cpu_series": "Ryzen R1600", "cpu_cores": "2",
        "ram_size": 8192, "serial": "2140PDN123456",
    }

    def test_reads_a_full_response(self):
        out = mod.normalise_system(self.SAMPLE)
        self.assertEqual(out["model"], "DS923+")
        self.assertEqual(out["tempC"], 41)
        self.assertEqual(out["uptimeSec"], 251 * 3600 + 22 * 60 + 19)

    def test_serial_is_reduced_to_a_suffix(self):
        out = mod.normalise_system(self.SAMPLE)
        self.assertEqual(out["serialSuffix"], "3456")
        self.assertNotIn("2140PDN", str(out))

    def test_empty_response_does_not_raise(self):
        out = mod.normalise_system({})
        self.assertEqual(out["model"], "")
        self.assertEqual(out["uptimeSec"], 0)


class Storage(unittest.TestCase):
    SAMPLE = {
        "volumes": [{
            "id": "volume_1", "status": "normal", "fs_type": "btrfs",
            "size": {"total": "7738958192640", "used": "3123456789012"},
        }],
        "disks": [
            {"id": "sata1", "name": "Drive 1", "status": "normal",
             "smart_status": "normal", "temp": 36},
            {"id": "sata2", "name": "Drive 2", "status": "normal",
             "smart_status": "normal", "temp": 38, "below_remain_life_thr": True},
        ],
    }

    def test_percentage_from_string_sizes(self):
        out = mod.normalise_storage(self.SAMPLE)
        self.assertAlmostEqual(out["volumes"][0]["percent"], 40.4, places=0)

    def test_threshold_trip_warns_even_when_smart_is_normal(self):
        out = mod.normalise_storage(self.SAMPLE)
        self.assertFalse(out["disks"][0]["warning"])
        self.assertTrue(out["disks"][1]["warning"])
        self.assertEqual(out["disks"][1]["smart"], "normal")

    def test_zero_total_does_not_divide_by_zero(self):
        out = mod.normalise_storage({"volumes": [{"id": "v", "size": {"total": "0", "used": "0"}}]})
        self.assertEqual(out["volumes"][0]["percent"], 0.0)

    def test_missing_sections(self):
        self.assertEqual(mod.normalise_storage({}), {"volumes": [], "disks": []})


class Utilisation(unittest.TestCase):
    def test_cpu_is_the_sum_of_three_loads(self):
        out = mod.normalise_utilisation(
            {"cpu": {"user_load": 12, "system_load": 5, "other_load": 1}})
        self.assertEqual(out["cpuPercent"], 18.0)

    def test_cpu_is_clamped(self):
        out = mod.normalise_utilisation(
            {"cpu": {"user_load": 80, "system_load": 30, "other_load": 10}})
        self.assertEqual(out["cpuPercent"], 100.0)

    def test_memory_prefers_real_usage(self):
        out = mod.normalise_utilisation({"memory": {"real_usage": 43, "total_real": 100}})
        self.assertEqual(out["memPercent"], 43)

    def test_memory_falls_back_to_arithmetic(self):
        out = mod.normalise_utilisation({"memory": {"total_real": 1000, "avail_real": 250}})
        self.assertEqual(out["memPercent"], 75.0)

    def test_total_row_is_not_double_counted(self):
        out = mod.normalise_utilisation({"network": [
            {"device": "total", "rx": 1000, "tx": 500},
            {"device": "eth0", "rx": 600, "tx": 300},
            {"device": "eth1", "rx": 400, "tx": 200},
        ]})
        self.assertEqual(out["netRxBps"], 1000)
        self.assertEqual(out["netTxBps"], 500)

    def test_without_a_total_row_interfaces_are_summed(self):
        out = mod.normalise_utilisation({"network": [
            {"device": "eth0", "rx": 600, "tx": 300},
            {"device": "eth1", "rx": 400, "tx": 200},
        ]})
        self.assertEqual(out["netRxBps"], 1000)

    def test_empty_response(self):
        out = mod.normalise_utilisation({})
        self.assertEqual(out["cpuPercent"], 0.0)
        self.assertEqual(out["memPercent"], 0.0)


class Encryption(unittest.TestCase):
    """encryption is a flag, not a state. Confirmed against DSM 7.4."""

    def test_flag_forms(self):
        self.assertFalse(mod.share_encryption({"encryption": 0}))
        self.assertTrue(mod.share_encryption({"encryption": 1}))

    def test_absent_means_not_encrypted(self):
        self.assertFalse(mod.share_encryption({}))
        self.assertFalse(mod.share_encryption({"encryption": ""}))

    def test_alternate_spellings(self):
        self.assertTrue(mod.share_encryption({"is_encrypted": True}))
        self.assertTrue(mod.share_encryption({"encryption": {"encrypted": True}}))


class Mounts(unittest.TestCase):
    MOUNTS = (
        "/dev/sda1 / btrfs rw,noatime 0 0\n"
        "//nas.local/Photos /home/me/mnt/nas/Photos cifs rw,uid=1000 0 0\n"
        "//nas.local/Time\\040Machine /home/me/mnt/nas/Time\\040Machine cifs rw 0 0\n"
        "//other.nas/Photos /home/me/mnt/other/Photos cifs rw 0 0\n"
    )

    def test_finds_only_this_hosts_shares(self):
        found = mod.local_mounts("nas.local", self.MOUNTS)
        self.assertIn("Photos", found)
        self.assertEqual(found["Photos"], "/home/me/mnt/nas/Photos")
        self.assertEqual(len(found), 2)

    def test_unescapes_spaces(self):
        found = mod.local_mounts("nas.local", self.MOUNTS)
        self.assertIn("Time Machine", found)
        self.assertEqual(found["Time Machine"], "/home/me/mnt/nas/Time Machine")

    def test_host_match_is_case_insensitive(self):
        self.assertIn("Photos", mod.local_mounts("NAS.LOCAL", self.MOUNTS))

    def test_no_mounts(self):
        self.assertEqual(mod.local_mounts("nas.local", ""), {})


class Shares(unittest.TestCase):
    DATA = {"shares": [
        {"name": "photos", "vol_path": "/volume1", "encryption": 0},
        {"name": "Backups", "vol_path": "/volume1", "encryption": 1},
    ]}

    def test_sorted_by_name(self):
        out = mod.normalise_shares(self.DATA, "nas", {"photos", "Backups"})
        self.assertEqual([s["name"] for s in out], ["Backups", "photos"])

    def test_encrypted_share_absent_from_file_station_is_locked(self):
        # A locked shared folder is not exported, so File Station cannot see
        # it. That absence is the only signal DSM gives.
        out = mod.normalise_shares(self.DATA, "nas", accessible={"photos"})
        locked = {s["name"]: s["locked"] for s in out}
        self.assertTrue(locked["Backups"])
        self.assertFalse(locked["photos"])

    def test_encrypted_share_that_is_visible_is_unlocked(self):
        out = mod.normalise_shares(self.DATA, "nas", accessible={"photos", "Backups"})
        locked = {s["name"]: s["locked"] for s in out}
        self.assertFalse(locked["Backups"])

    def test_unknown_when_file_station_cannot_answer(self):
        # Guessing "unlocked" here is what sent a mount at a locked share.
        out = mod.normalise_shares(self.DATA, "nas", accessible=None)
        locked = {s["name"]: s["locked"] for s in out}
        self.assertIsNone(locked["Backups"])
        self.assertFalse(locked["photos"])

    def test_nameless_entries_are_dropped(self):
        out = mod.normalise_shares({"shares": [{"vol_path": "/volume1"}]}, "nas")
        self.assertEqual(out, [])


class Logs(unittest.TestCase):
    def test_reads_either_key_naming(self):
        out = mod.normalise_logs(
            {"items": [{"level": "WARN", "logtime": "2026-09-10 12:00", "descr": "disk hot"}]}, 10)
        self.assertEqual(out[0]["level"], "warn")
        self.assertEqual(out[0]["message"], "disk hot")

    def test_honours_the_limit(self):
        rows = [{"descr": f"entry {i}"} for i in range(50)]
        self.assertEqual(len(mod.normalise_logs({"logs": rows}, 5)), 5)

    def test_unexpected_payload_is_not_fatal(self):
        self.assertEqual(mod.normalise_logs({"items": "nope"}, 10), [])
        self.assertEqual(mod.normalise_logs({}, 10), [])



class TlsFailureMessages(unittest.TestCase):
    """OpenSSL says "wrong version number"; the user needs to know what to change."""

    def test_https_against_the_http_port_names_the_fix(self):
        message = mod.describe_tls_failure(
            Exception("[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1082)"), 5000)
        self.assertIn("5000", message)
        self.assertIn("5001", message)
        self.assertNotIn("WRONG_VERSION_NUMBER", message)

    def test_https_against_another_port(self):
        message = mod.describe_tls_failure(
            Exception("[SSL: WRONG_VERSION_NUMBER] wrong version number"), 8080)
        self.assertIn("8080", message)
        self.assertIn("5001", message)

    def test_certificate_failure_is_not_confused_with_a_port_mistake(self):
        message = mod.describe_tls_failure(
            Exception("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"), 5001)
        self.assertIn("certificate", message.lower())
        self.assertNotIn("5000", message)

    def test_unknown_failure_still_carries_the_detail(self):
        message = mod.describe_tls_failure(Exception("something odd"), 5001)
        self.assertIn("something odd", message)


class HostResolution(unittest.TestCase):
    def test_a_literal_address_is_not_resolved(self):
        # Short-circuiting matters: a NAS given by IP should never touch the
        # resolver, which is where the multi-second mDNS stall lives.
        self.assertEqual(mod.resolve_host("192.168.1.100"), "192.168.1.100")

    def test_cache_round_trip(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        original = mod.DNS_PATH
        mod.DNS_PATH = path
        try:
            mod._write_dns_cache({"box.local": {"ip": "10.0.0.5",
                                                "expires": time.time() + 60}})
            self.assertEqual(mod.resolve_host("box.local"), "10.0.0.5")
            mod.forget_host("box.local")
            self.assertEqual(mod._read_dns_cache(), {})
        finally:
            mod.DNS_PATH = original
            os.remove(path)

    def test_expired_entry_is_not_used(self):
        handle, path = tempfile.mkstemp()
        os.close(handle)
        original = mod.DNS_PATH
        mod.DNS_PATH = path
        try:
            mod._write_dns_cache({"gone.invalid": {"ip": "10.0.0.5",
                                                   "expires": time.time() - 1}})
            # Expired, and the name does not resolve, so it must raise rather
            # than hand back a stale address.
            with self.assertRaises(SystemExit):
                mod.resolve_host("gone.invalid")
        finally:
            mod.DNS_PATH = original
            os.remove(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
