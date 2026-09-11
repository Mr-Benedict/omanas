"""Tests for shape(), which is what makes `diagnostics` and `probe` safe.

Both commands exist so someone can paste a report into a bug thread. The
whole guarantee is that the report says which fields a DSM serves and what
type each holds, and nothing about what this particular NAS contains. A
regression here leaks a serial number or a list of share names into a public
issue, which is not the sort of bug that announces itself, so the tests are
written as "this string must not appear in the output" rather than as
assertions about the shape of the shape.
"""

import json
import unittest

from helpers import omanas

mod = omanas()

# Deliberately recognisable: every one of these is something a real NAS would
# put in a response and nobody would want in a bug report.
SECRETS = [
    "2140PDN123456",        # serial
    "Tax Returns",          # share name
    "/volume1/Tax Returns", # volume path
    "ben@example.com",      # account
    "192.168.1.20",         # address
]

SAMPLE = {
    "serial": "2140PDN123456",
    "model": "DS923+",
    "temperature": 41,
    "enabled": True,
    "sys_status": None,
    "empty_field": "",
    "shares": [
        {"name": "Tax Returns", "vol_path": "/volume1/Tax Returns",
         "encryption": 1, "quota": "10737418240"},
        {"name": "Photos", "vol_path": "/volume1/Photos", "encryption": 0,
         "recyclebin": True},
    ],
    "network": {"ip": "192.168.1.20", "owner": "ben@example.com"},
}


class NothingLeaks(unittest.TestCase):
    def test_no_value_survives_into_the_report(self):
        report = json.dumps(mod.shape(SAMPLE))
        for secret in SECRETS:
            self.assertNotIn(secret, report, secret)

    def test_field_names_do_survive(self):
        # The schema is the thing being reported, so keys stay verbatim.
        report = mod.shape(SAMPLE)
        self.assertIn("serial", report)
        self.assertIn("vol_path", report["shares"]["items"])

    def test_numbers_and_booleans_are_verbatim(self):
        # Whether a field is bytes, kilobytes or a percentage is the entire
        # reason to read the report, and a number identifies nobody.
        report = mod.shape(SAMPLE)
        self.assertEqual(report["temperature"], 41)
        self.assertIs(report["enabled"], True)
        self.assertIsNone(report["sys_status"])

    def test_the_report_is_json_serialisable(self):
        # It is printed with json.dumps(sort_keys=True); a set or a tuple
        # sneaking through would make the command fail at the last line.
        json.dumps(mod.shape(SAMPLE), sort_keys=True)


class Strings(unittest.TestCase):
    """A string is reduced to what the normalisation layer needs to know."""

    def test_a_numeric_string_is_flagged_as_one(self):
        # DSM returns sizes as strings; that fact is why anyone probes.
        self.assertEqual(mod.shape("7738958192640"), "str(numeric,len=13)")
        self.assertEqual(mod.shape("-5"), "str(numeric,len=2)")
        self.assertEqual(mod.shape("40.4"), "str(numeric,len=4)")

    def test_a_word_is_not(self):
        self.assertEqual(mod.shape("normal"), "str(len=6)")

    def test_empty_is_distinguishable_from_absent(self):
        # first_key() treats "" as absent, so telling the two apart matters.
        self.assertEqual(mod.shape(""), "str(empty)")
        self.assertIsNone(mod.shape(None))


class Lists(unittest.TestCase):
    def test_count_is_reported_without_the_rows(self):
        report = mod.shape(SAMPLE)["shares"]
        self.assertEqual(report["type"], "list")
        self.assertEqual(report["count"], 2)

    def test_keys_are_unioned_across_rows(self):
        # A field DSM sets on the second disk but not the first is exactly
        # what the probe is for, so describing only row zero would hide it.
        keys = mod.shape(SAMPLE)["shares"]["items"].keys()
        self.assertIn("quota", keys)       # first row only
        self.assertIn("recyclebin", keys)  # second row only

    def test_empty_list(self):
        self.assertEqual(mod.shape([]), {"type": "list", "count": 0, "items": None})

    def test_a_list_of_scalars(self):
        self.assertEqual(mod.shape([1, 2, 3])["items"], 1)


class Recursion(unittest.TestCase):
    def test_deep_nesting_terminates(self):
        deep = current = {}
        for _ in range(50):
            current["next"] = {}
            current = current["next"]
        self.assertIn("...", json.dumps(mod.shape(deep)))

    def test_a_cycle_does_not_hang(self):
        # Nothing in DSM's JSON can be cyclic, but shape() is the last thing
        # that runs before a report is printed and must not be the reason a
        # diagnostics run never returns.
        node: dict = {}
        node["self"] = node
        json.dumps(mod.shape(node))


class DiagnosticsUsesIt(unittest.TestCase):
    def test_shape_is_defined(self):
        # cmd_diagnostics and cmd_probe --call both call shape() at the point
        # where a report is assembled. It went missing once, and the failure
        # was a NameError at the end of a round trip to the NAS.
        self.assertTrue(callable(getattr(mod, "shape", None)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
