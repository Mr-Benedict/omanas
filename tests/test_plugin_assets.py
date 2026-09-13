"""Sanity checks on the things the shell reads rather than Python does.

Omarchy loads manifest.json and the QML files; nothing in the Python suite
touches either, so a truncated component or a settings key that exists in the
schema but not in the defaults would ship unnoticed. The shell's own failure
for these is a widget that silently does not appear, which is a slow thing to
debug from the other end.
"""

import json
import os
import re
import stat
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


MANIFEST = json.loads(read("manifest.json"))


def qml_files():
    found = []
    for directory, _, names in os.walk(ROOT):
        if ".git" in directory:
            continue
        found += [os.path.join(directory, name) for name in names
                  if name.endswith((".qml", ".js"))]
    return sorted(found)


class Manifest(unittest.TestCase):
    def test_it_is_valid_json(self):
        json.loads(read("manifest.json"))

    def test_the_required_keys_are_present(self):
        for key in ["schemaVersion", "id", "name", "version", "license",
                    "description", "kinds", "entryPoints"]:
            self.assertIn(key, MANIFEST, key)

    def test_the_id_is_a_reverse_dns_name(self):
        # It is also the directory name the plugin is installed under, so a
        # change here silently orphans an existing install.
        self.assertRegex(MANIFEST["id"], r"^[a-z0-9]+(\.[a-z0-9-]+)+$")

    def test_the_version_is_a_version(self):
        self.assertRegex(MANIFEST["version"], r"^\d+\.\d+\.\d+$")

    def test_every_entry_point_names_a_file_that_exists(self):
        for kind, path in MANIFEST["entryPoints"].items():
            with self.subTest(kind=kind):
                self.assertTrue(os.path.isfile(os.path.join(ROOT, path)), path)

    def test_every_declared_kind_has_an_entry_point(self):
        # "bar-widget" is served by entryPoints.barWidget.
        for kind in MANIFEST["kinds"]:
            camel = re.sub(r"-(.)", lambda m: m.group(1).upper(), kind)
            self.assertIn(camel, MANIFEST["entryPoints"], kind)

    def test_the_licence_matches_the_file_shipped(self):
        self.assertEqual(MANIFEST["license"], "GPL-3.0-or-later")
        self.assertIn("GNU GENERAL PUBLIC LICENSE", read("LICENSE"))


class Settings(unittest.TestCase):
    """The settings schema and the defaults have to describe the same thing."""

    WIDGET = MANIFEST["barWidget"]
    SCHEMA = {item["key"]: item for item in WIDGET["schema"]}
    DEFAULTS = WIDGET["defaults"]

    def test_every_schema_key_has_a_default(self):
        # A settings row with no default renders empty and writes an empty
        # value back the first time it is touched.
        for key in self.SCHEMA:
            self.assertIn(key, self.DEFAULTS, key)

    def test_every_default_is_settable(self):
        for key in self.DEFAULTS:
            self.assertIn(key, self.SCHEMA, key)

    def test_the_two_defaults_agree(self):
        # defaults[key] is what the widget starts with; schema defaultValue is
        # what the settings panel shows. They being different is the sort of
        # bug that only shows up after someone opens the panel.
        for key, item in self.SCHEMA.items():
            self.assertEqual(item["defaultValue"], self.DEFAULTS[key], key)

    def test_numeric_defaults_sit_inside_their_own_bounds(self):
        for key, item in self.SCHEMA.items():
            if item["type"] == "integer":
                with self.subTest(key=key):
                    self.assertGreaterEqual(item["defaultValue"], item["min"])
                    self.assertLessEqual(item["defaultValue"], item["max"])

    def test_an_enum_default_is_one_of_its_options(self):
        for key, item in self.SCHEMA.items():
            if item["type"] == "enum":
                values = [option["value"] for option in item["options"]]
                self.assertIn(item["defaultValue"], values, key)

    def test_every_setting_has_a_label(self):
        for key, item in self.SCHEMA.items():
            self.assertTrue(item.get("label"), key)

    def test_the_resource_poll_is_faster_than_the_status_refresh(self):
        # The resource graph is the thing that has to look live; a default
        # slower than the full status refresh would make it the opposite.
        self.assertLess(self.DEFAULTS["resourcePollSec"],
                        self.DEFAULTS["refreshIntervalSec"])

    def test_the_mount_root_default_matches_what_the_helper_uses(self):
        self.assertIn("--mount-root", read("bin", "omanas"))
        self.assertIn(self.DEFAULTS["mountRoot"], read("bin", "omanas"))

    def test_the_mount_root_is_described_as_a_shortcut(self):
        # It stopped being where shares are mounted: the helper derives that
        # itself, under /mnt/omanas. A label still promising otherwise would
        # have people typing a path that does nothing.
        label = self.SCHEMA["mountRoot"]["label"]
        self.assertIn("/mnt/omanas", label)
        self.assertIn("/mnt/omanas", read("bin", "omanas"))


# A `/` starts a regex literal only where a value may begin. Without this,
# `replace(/^file:\/\//, "")` reads as a comment and the rest of the line
# disappears; with it, QML's own JavaScript scans correctly.
BEFORE_REGEX = set("(,=:[!&|?{};") | {"return", "typeof", "case", "in", "of"}


def delimiters(text):
    """Count (){}[] outside strings, comments and regex literals.

    A real parser is qmllint's job. This is only enough to notice a file that
    stops in the middle, which is the failure that would otherwise reach the
    shell as a widget that silently does not appear.
    """
    counts = {ch: 0 for ch in "(){}[]"}
    index, length = 0, len(text)
    previous = ""
    while index < length:
        ch = text[index]
        pair = text[index:index + 2]
        if pair == "/*":
            index = text.find("*/", index + 2)
            index = length if index < 0 else index + 2
            continue
        if pair == "//":
            index = text.find("\n", index)
            index = length if index < 0 else index
            continue
        if ch in "\"'`":
            index += 1
            while index < length and text[index] != ch:
                index += 2 if text[index] == "\\" else 1
            index += 1
            continue
        if ch == "/" and previous in BEFORE_REGEX:
            index += 1
            in_class = False
            while index < length and (in_class or text[index] != "/"):
                if text[index] == "\\":
                    index += 1
                elif text[index] == "[":
                    in_class = True
                elif text[index] == "]":
                    in_class = False
                index += 1
            index += 1
            continue
        if ch in counts:
            counts[ch] += 1
        if not ch.isspace():
            previous = ch if not (ch.isalnum() or ch == "_") else _word(text, index)
        index += 1
    return counts


def _word(text, index):
    start = index
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        start -= 1
    end = index
    while end < len(text) and (text[end].isalnum() or text[end] == "_"):
        end += 1
    return text[start:end]


class Qml(unittest.TestCase):
    """Not a substitute for qmllint, but it catches a truncated file."""

    def test_delimiters_balance(self):
        for path in qml_files():
            relative = os.path.relpath(path, ROOT)
            with self.subTest(path=relative):
                counts = delimiters(read(relative))
                for opener, closer in [("{", "}"), ("(", ")"), ("[", "]")]:
                    self.assertEqual(counts[opener], counts[closer],
                                     f"unbalanced {opener}{closer}")

    def test_the_scanner_understands_what_it_is_reading(self):
        # The checks above are only worth anything if this does not miscount.
        # Each of these once did.
        self.assertEqual(delimiters('a("//not a comment")')["("], 1)
        self.assertEqual(delimiters('x.replace(/^file:\\/\\//, "")')["("], 1)
        self.assertEqual(delimiters("// ( ( (\nf()")["("], 1)
        self.assertEqual(delimiters("/* ( ( */ f()")["("], 1)
        self.assertEqual(delimiters('"\\"(" " ) "')["("], 0)
        self.assertEqual(delimiters("a = 1 / 2 / 3; f(())")["("], 2)

    def test_no_file_is_empty(self):
        for path in qml_files():
            relative = os.path.relpath(path, ROOT)
            with self.subTest(path=relative):
                self.assertTrue(read(relative).strip())

    def test_every_qml_file_imports_something(self):
        for path in qml_files():
            if not path.endswith(".qml"):
                continue
            relative = os.path.relpath(path, ROOT)
            with self.subTest(path=relative):
                self.assertRegex(read(relative), r"(?m)^\s*import\s+\S+")

    def test_local_components_referenced_by_path_exist(self):
        # ui/UsageBar.qml and friends are loaded by relative path; a rename
        # that misses a call site is a component that never renders.
        for path in qml_files():
            body = read(os.path.relpath(path, ROOT))
            for match in re.findall(r'["\'](\.{1,2}/[\w./-]+\.qml)["\']', body):
                target = os.path.normpath(os.path.join(os.path.dirname(path), match))
                with self.subTest(source=os.path.relpath(path, ROOT), target=match):
                    self.assertTrue(os.path.isfile(target), match)


class Scripts(unittest.TestCase):
    def test_both_helpers_are_executable_with_a_shebang(self):
        for name in ["omanas", "omanas-mount"]:
            path = os.path.join(ROOT, "bin", name)
            with self.subTest(name=name):
                self.assertTrue(os.stat(path).st_mode & stat.S_IXUSR)
                self.assertTrue(read("bin", name).startswith("#!/usr/bin/env python3"))

    def test_the_helpers_import_only_the_standard_library(self):
        # The README promises the plugin installs by cloning and nothing else.
        # A pip dependency would break that quietly on someone else's machine.
        allowed = set(__import__("sys").stdlib_module_names)
        for name in ["omanas", "omanas-mount"]:
            body = read("bin", name)
            modules = re.findall(r"(?m)^(?:import|from)\s+([\w.]+)", body)
            for module in modules:
                root = module.split(".")[0]
                if root == "__future__":
                    continue
                with self.subTest(name=name, module=module):
                    self.assertIn(root, allowed, module)

    def test_the_client_never_names_a_mountpoint(self):
        # The root helper derives the path from the account it is mounting
        # for. A client that could name one would reopen the race that
        # moving the mounts out of the user's home closed.
        self.assertNotIn("--mountpoint", read("bin", "omanas"))

    def test_the_version_the_helper_reports_matches_the_manifest(self):
        self.assertIn(f'"omanas": "{MANIFEST["version"]}"', read("bin", "omanas"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
