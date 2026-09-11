"""Loading the two helpers, which are scripts rather than importable modules.

bin/omanas and bin/omanas-mount have no .py suffix on purpose: they are run,
not imported. Tests still need them as modules, so they are loaded by path.
SourceFileLoader.load_module() would do it in one line but is removed in
Python 3.15, so the spec machinery is used directly.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin")


def load(name: str, filename: str):
    path = os.path.join(BIN, filename)
    spec = importlib.util.spec_from_loader(
        name, importlib.machinery.SourceFileLoader(name, path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def omanas():
    return load("omanas", "omanas")


def omanas_mount():
    return load("omanas_mount", "omanas-mount")


HELPER = os.path.join(BIN, "omanas")
MOUNT_HELPER = os.path.join(BIN, "omanas-mount")


@contextlib.contextmanager
def quiet():
    """Swallow what a helper prints on its way to failing.

    Both helpers report by printing JSON to stdout, including on the refusal
    paths these tests exist to drive. Without this the suite's own output is
    buried under refusals that are the expected result.
    """
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        yield buffer
