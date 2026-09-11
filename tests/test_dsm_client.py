"""Tests for the transport: error translation, discovery, calls, sessions.

Nothing here touches a network. The DSM endpoints this plugin uses are known
from reverse-engineered clients rather than from documentation, so what these
tests pin down is our side of the contract -- that a credential never reaches
a query string, that a pinned certificate is compared rather than merely
recorded, that a cached API map belongs to the host it was fetched from --
because those are the parts that stay true across DSM releases.
"""

import http.client
import json
import os
import ssl
import tempfile
import time
import unittest

from helpers import omanas

mod = omanas()


class FakeResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self._payload = payload if isinstance(payload, str) else json.dumps(payload)

    def read(self):
        return self._payload.encode("utf-8")


class FakeConnection:
    """Stands in for the one kept-alive connection a Dsm holds.

    Records every request so a test can assert on the method, the target and
    the body -- which is where 'the password must not be in the query string'
    is actually checked.
    """

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []
        self.closed = False

    def request(self, method, target, body, headers):
        self.requests.append({"method": method, "target": target,
                              "body": body, "headers": headers})

    def getresponse(self):
        nxt = self.responses.pop(0) if self.responses else FakeResponse({"success": True})
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def close(self):
        self.closed = True


CONFIG = {"host": "nas.local", "username": "ben", "https": True, "port": 5001}

# One API map, enough for entry() to resolve the endpoints the panel wants.
APIS = {
    "SYNO.API.Auth": {"path": "auth.cgi", "minVersion": 1, "maxVersion": 7},
    "SYNO.Core.System": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 3},
    "SYNO.Core.Share": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.System.Utilization": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Storage.CGI.Storage": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
    "SYNO.Core.SystemLog": {"path": "entry.cgi", "minVersion": 1, "maxVersion": 1},
}


class Sandbox(unittest.TestCase):
    """Every cache path redirected into a scratch directory.

    The real ones live under ~/.cache/omanas, and a test suite that writes
    there would trample a working install and read back its session.
    """

    def setUp(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(self._clean, directory)
        for name in ("CACHE_DIR", "SESSION_PATH", "DNS_PATH", "APIS_PATH",
                     "CONFIG_DIR", "CONFIG_PATH"):
            self.addCleanup(setattr, mod, name, getattr(mod, name))
        mod.CACHE_DIR = mod.CONFIG_DIR = directory
        mod.SESSION_PATH = os.path.join(directory, "session.json")
        mod.DNS_PATH = os.path.join(directory, "dns.json")
        mod.APIS_PATH = os.path.join(directory, "apis.json")
        mod.CONFIG_PATH = os.path.join(directory, "config.json")
        # Nothing may resolve a name; an unreachable NAS in CI must not turn
        # into a five-second stall or a flaky failure.
        self.real_resolve_host = mod.resolve_host
        self.addCleanup(setattr, mod, "resolve_host", mod.resolve_host)
        mod.resolve_host = lambda host: "10.0.0.9"

    def _clean(self, directory):
        for entry in os.listdir(directory):
            os.remove(os.path.join(directory, entry))
        os.rmdir(directory)

    def dsm(self, config=None, conn=None, apis=APIS):
        client = mod.Dsm(dict(config or CONFIG))
        if apis is not None:
            client.apis = dict(apis)
        if conn is not None:
            client._conn = conn
            client._connect = lambda: conn
        return client


class Errors(unittest.TestCase):
    def test_auth_codes_are_named(self):
        self.assertEqual(mod.DsmError(400).describe(), "Wrong username or password")
        self.assertIn("Two-factor", mod.DsmError(403).describe())

    def test_crypto_codes_have_their_own_range(self):
        # SYNO.Core.Share.Crypto reports in 33xx, not in the common range.
        self.assertIn("passphrase", mod.DsmError(3308).describe())

    def test_common_codes(self):
        self.assertIn("does not exist", mod.DsmError(102).describe())

    def test_an_unknown_code_still_says_which_call_produced_it(self):
        message = mod.DsmError(9999, "SYNO.Core.Share", "list").describe()
        self.assertIn("9999", message)
        self.assertIn("SYNO.Core.Share.list", message)

    def test_a_known_code_carries_the_call_too(self):
        message = mod.DsmError(105, "SYNO.Core.System", "info").describe()
        self.assertIn("privilege", message)
        self.assertIn("SYNO.Core.System.info", message)

    def test_code_is_an_int_even_when_dsm_sends_a_string(self):
        self.assertEqual(mod.DsmError("400").code, 400)


class Construction(Sandbox):
    def test_port_follows_the_scheme(self):
        self.assertEqual(mod.Dsm({"host": "n", "https": True}).port, 5001)
        self.assertEqual(mod.Dsm({"host": "n", "https": False}).port, 5000)

    def test_an_explicit_port_wins(self):
        self.assertEqual(mod.Dsm({"host": "n", "https": True, "port": 8443}).port, 8443)

    def test_base_url(self):
        self.assertEqual(self.dsm().base, "https://nas.local:5001")
        self.assertEqual(
            self.dsm({"host": "nas.local", "https": False, "port": 5000}).base,
            "http://nas.local:5000")

    def test_no_host_is_an_actionable_refusal(self):
        with self.assertRaises(SystemExit) as caught:
            mod.Dsm({})
        self.assertIn("omanas configure", str(caught.exception))


class Pinning(unittest.TestCase):
    def test_a_pin_replaces_verification_rather_than_adding_to_it(self):
        # A self-signed NAS certificate cannot pass the default check, so the
        # pin is the check. Leaving CERT_REQUIRED on would fail every connect.
        ctx = mod.PinnedContext({"certFingerprint": "ab" * 32}).build()
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)

    def test_a_real_certificate_is_still_verified(self):
        ctx = mod.PinnedContext({"verifyTls": True}).build()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_verification_can_be_turned_off_outright(self):
        ctx = mod.PinnedContext({"verifyTls": False}).build()
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)


class Requests(Sandbox):
    def test_a_get_puts_the_query_in_the_target(self):
        conn = FakeConnection(FakeResponse({"success": True, "data": {"model": "DS923+"}}))
        dsm = self.dsm(conn=conn)
        dsm.call("SYNO.Core.System", "info")
        sent = conn.requests[0]
        self.assertEqual(sent["method"], "GET")
        self.assertIn("api=SYNO.Core.System", sent["target"])
        self.assertIsNone(sent["body"])

    def test_a_post_puts_it_in_the_body_instead(self):
        conn = FakeConnection(FakeResponse({"success": True, "data": {}}))
        dsm = self.dsm(conn=conn)
        dsm.call("SYNO.Core.Share", "list", post=True, params={"shareType": "all"})
        sent = conn.requests[0]
        self.assertEqual(sent["method"], "POST")
        self.assertNotIn("shareType", sent["target"])
        self.assertIn("shareType=all", sent["body"])

    def test_the_host_header_carries_the_name_the_address_lost(self):
        # The connection is made to a cached address, so DSM's virtual-host
        # handling only sees the name if it travels in the header.
        conn = FakeConnection(FakeResponse({"success": True}))
        self.dsm(conn=conn).call("SYNO.Core.System", "info")
        self.assertEqual(conn.requests[0]["headers"]["Host"], "nas.local")

    def test_the_session_id_rides_along_once_there_is_one(self):
        conn = FakeConnection(FakeResponse({"success": True}), FakeResponse({"success": True}))
        dsm = self.dsm(conn=conn)
        dsm.call("SYNO.Core.System", "info")
        self.assertNotIn("_sid", conn.requests[0]["target"])
        dsm.sid = "abc123"
        dsm.call("SYNO.Core.System", "info")
        self.assertIn("_sid=abc123", conn.requests[1]["target"])

    def test_the_version_used_is_the_maximum_this_nas_offers(self):
        conn = FakeConnection(FakeResponse({"success": True}))
        self.dsm(conn=conn).call("SYNO.Core.System", "info")
        self.assertIn("version=3", conn.requests[0]["target"])

    def test_an_explicit_version_overrides_it(self):
        conn = FakeConnection(FakeResponse({"success": True}))
        self.dsm(conn=conn).call("SYNO.Core.System", "info", version=1)
        self.assertIn("version=1", conn.requests[0]["target"])

    def test_success_false_becomes_a_named_error(self):
        conn = FakeConnection(FakeResponse({"success": False, "error": {"code": 105}}))
        with self.assertRaises(mod.DsmError) as caught:
            self.dsm(conn=conn).call("SYNO.Core.System", "info")
        self.assertEqual(caught.exception.code, 105)
        self.assertEqual(caught.exception.api, "SYNO.Core.System")

    def test_a_success_with_no_data_is_not_an_error(self):
        # logout answers this way, and treating it as a failure would leave a
        # session id behind on every sign-out.
        conn = FakeConnection(FakeResponse({"success": True}))
        self.assertEqual(self.dsm(conn=conn).call("SYNO.API.Auth", "logout"), {})

    def test_a_non_200_says_which_host_refused(self):
        conn = FakeConnection(FakeResponse({}, status=500))
        with self.assertRaises(SystemExit) as caught:
            self.dsm(conn=conn).call("SYNO.Core.System", "info")
        self.assertIn("500", str(caught.exception))

    def test_html_instead_of_json_suggests_the_port(self):
        # Pointing the plugin at a web server rather than at DSM gives a page,
        # not a payload, and "expecting value: line 1" would help nobody.
        conn = FakeConnection(FakeResponse("<html>Not DSM</html>"))
        with self.assertRaises(SystemExit) as caught:
            self.dsm(conn=conn).call("SYNO.Core.System", "info")
        self.assertIn("port", str(caught.exception).lower())

    def test_a_tls_error_is_translated_rather_than_reported_raw(self):
        conn = FakeConnection(ssl.SSLError("[SSL: WRONG_VERSION_NUMBER] wrong version number"))
        dsm = self.dsm({"host": "nas.local", "username": "ben", "https": True, "port": 5000},
                       conn=conn)
        with self.assertRaises(SystemExit) as caught:
            dsm.call("SYNO.Core.System", "info")
        self.assertIn("5001", str(caught.exception))
        self.assertNotIn("WRONG_VERSION_NUMBER", str(caught.exception))

    def test_a_dropped_keepalive_is_remade_once(self):
        """The second call in a process must not fail because DSM hung up."""
        attempts = []

        class Dropping(FakeConnection):
            def getresponse(self):
                attempts.append(1)
                if len(attempts) == 1:
                    raise http.client.RemoteDisconnected("closed")
                return FakeResponse({"success": True, "data": {"ok": 1}})

        conn = Dropping()
        dsm = self.dsm(conn=conn)
        # _connect is pinned to the same object, so the retry reuses it.
        self.assertEqual(dsm.call("SYNO.Core.System", "info"), {"ok": 1})
        self.assertEqual(len(attempts), 2)

    def test_a_second_failure_gives_up_with_the_address(self):
        conn = FakeConnection(OSError("no route to host"), OSError("no route to host"))
        with self.assertRaises(SystemExit) as caught:
            self.dsm(conn=conn).call("SYNO.Core.System", "info")
        self.assertIn("nas.local:5001", str(caught.exception))

    def test_plain_http_on_the_tls_port_names_the_mistake(self):
        conn = FakeConnection(OSError("bad status line"), OSError("bad status line"))
        dsm = self.dsm({"host": "nas.local", "username": "ben", "https": False, "port": 5001},
                       conn=conn)
        with self.assertRaises(SystemExit) as caught:
            dsm.call("SYNO.Core.System", "info")
        self.assertIn("HTTPS", str(caught.exception))


class Discovery(Sandbox):
    def test_the_map_is_fetched_once_and_cached_on_disk(self):
        conn = FakeConnection(FakeResponse({"success": True, "data": APIS}))
        dsm = self.dsm(conn=conn, apis=None)
        self.assertEqual(dsm.discover(), APIS)
        self.assertEqual(len(conn.requests), 1)

        # A second process starts with nothing in memory and must not pay for
        # the map again; the resource poll runs every couple of seconds.
        fresh = self.dsm(conn=FakeConnection(), apis=None)
        self.assertEqual(fresh.discover(), APIS)

    def test_a_cached_map_belongs_to_the_host_it_came_from(self):
        self.dsm(conn=FakeConnection(FakeResponse({"success": True, "data": APIS})),
                 apis=None).discover()
        other = self.dsm({"host": "other.local", "username": "ben"}, apis=None)
        self.assertIsNone(other._cached_apis())

    def test_an_expired_map_is_not_used(self):
        with open(mod.APIS_PATH, "w") as handle:
            json.dump({"host": "nas.local", "apis": APIS,
                       "expires": time.time() - 1}, handle)
        self.assertIsNone(self.dsm(apis=None)._cached_apis())

    def test_a_corrupt_map_is_ignored_rather_than_fatal(self):
        with open(mod.APIS_PATH, "w") as handle:
            handle.write("{not json")
        self.assertIsNone(self.dsm(apis=None)._cached_apis())

    def test_forget_apis_clears_both_copies(self):
        dsm = self.dsm()
        dsm._store_apis(APIS)
        dsm.forget_apis()
        self.assertEqual(dsm.apis, {})
        self.assertFalse(os.path.exists(mod.APIS_PATH))

    def test_entry_resolves_a_path_and_a_version(self):
        self.assertEqual(self.dsm().entry("SYNO.Core.System"), ("entry.cgi", 3))

    def test_an_api_missing_from_a_stale_map_costs_one_fresh_lookup(self):
        # A DSM upgrade adds APIs. Reporting 'not supported' from a cached map
        # would strand the panel until the cache expired an hour later.
        grown = dict(APIS, **{"SYNO.Core.Share.Crypto": {"path": "entry.cgi", "maxVersion": 1}})
        conn = FakeConnection(FakeResponse({"success": True, "data": grown}))
        dsm = self.dsm(conn=conn)
        self.assertEqual(dsm.entry("SYNO.Core.Share.Crypto"), ("entry.cgi", 1))

    def test_an_api_this_nas_really_lacks_is_reported_as_missing(self):
        conn = FakeConnection(FakeResponse({"success": True, "data": APIS}))
        with self.assertRaises(mod.DsmError) as caught:
            self.dsm(conn=conn).entry("SYNO.LogCenter.Log")
        self.assertEqual(caught.exception.code, 102)


class Sessions(Sandbox):
    def test_round_trip(self):
        dsm = self.dsm()
        dsm.sid = "sid-1"
        dsm.save_session()
        self.assertTrue(self.dsm().load_session())

    def test_the_session_file_is_not_world_readable(self):
        # It holds a live session id; 0644 would hand it to every local user.
        dsm = self.dsm()
        dsm.sid = "sid-1"
        dsm.save_session()
        self.assertEqual(os.stat(mod.SESSION_PATH).st_mode & 0o777, 0o600)

    def test_a_session_for_another_account_is_not_reused(self):
        dsm = self.dsm()
        dsm.sid = "sid-1"
        dsm.save_session()
        other = self.dsm({"host": "nas.local", "username": "someone-else"})
        self.assertFalse(other.load_session())

    def test_a_session_for_another_host_is_not_reused(self):
        dsm = self.dsm()
        dsm.sid = "sid-1"
        dsm.save_session()
        self.assertFalse(self.dsm({"host": "other.local", "username": "ben"}).load_session())

    def test_an_expired_session_is_not_reused(self):
        with open(mod.SESSION_PATH, "w") as handle:
            json.dump({"host": "nas.local", "account": "ben", "sid": "old",
                       "expires": time.time() - 1}, handle)
        self.assertFalse(self.dsm().load_session())

    def test_no_session_file_at_all(self):
        self.assertFalse(self.dsm().load_session())

    def test_logout_removes_the_file_even_when_dsm_refuses(self):
        dsm = self.dsm(conn=FakeConnection(
            FakeResponse({"success": False, "error": {"code": 106}})))
        dsm.sid = "sid-1"
        dsm.save_session()
        dsm.logout()
        self.assertFalse(os.path.exists(mod.SESSION_PATH))


class Login(Sandbox):
    def setUp(self):
        super().setUp()
        self.stored = {}
        self.addCleanup(setattr, mod, "secret_lookup", mod.secret_lookup)
        self.addCleanup(setattr, mod, "secret_store", mod.secret_store)
        mod.secret_lookup = lambda config, kind: self.stored.get(kind)
        mod.secret_store = lambda config, kind, value, label: self.stored.__setitem__(kind, value)

    def test_the_password_travels_in_a_post_body_not_a_query_string(self):
        # DSM's own access log records query strings. A password in one is a
        # password written to a file on the NAS, indefinitely.
        conn = FakeConnection(FakeResponse({"success": True, "data": {"sid": "s"}}))
        self.dsm(conn=conn).login(password="hunter2")
        sent = conn.requests[0]
        self.assertEqual(sent["method"], "POST")
        self.assertNotIn("hunter2", sent["target"])
        self.assertIn("passwd=hunter2", sent["body"])

    def test_a_cached_session_skips_the_round_trip(self):
        dsm = self.dsm()
        dsm.sid = "sid-1"
        dsm.save_session()
        conn = FakeConnection()
        reused = self.dsm(conn=conn).login()
        self.assertTrue(reused["reused"])
        self.assertEqual(conn.requests, [])

    def test_force_ignores_a_cached_session(self):
        primed = self.dsm()
        primed.sid = "sid-1"
        primed.save_session()
        conn = FakeConnection(FakeResponse({"success": True, "data": {"sid": "s2"}}))
        self.dsm(conn=conn).login(password="hunter2", force=True)
        self.assertEqual(len(conn.requests), 1)

    def test_no_password_anywhere_is_an_actionable_refusal(self):
        with self.assertRaises(SystemExit) as caught:
            self.dsm(conn=FakeConnection()).login()
        self.assertIn("keyring", str(caught.exception))

    def test_a_device_token_is_kept_so_2fa_asks_once_per_machine(self):
        conn = FakeConnection(FakeResponse({"success": True, "data": {"sid": "s", "did": "dev-1"}}))
        self.dsm(conn=conn).login(password="hunter2", otp="123456")
        self.assertEqual(self.stored["device_id"], "dev-1")

    def test_the_stored_token_is_sent_when_no_code_was_typed(self):
        self.stored["device_id"] = "dev-1"
        conn = FakeConnection(FakeResponse({"success": True, "data": {"sid": "s"}}))
        self.dsm(conn=conn).login(password="hunter2")
        self.assertIn("device_id=dev-1", conn.requests[0]["body"])

    def test_a_typed_code_takes_precedence_over_the_token(self):
        # Retyping a code is how someone recovers from a stale token; sending
        # the token alongside it would let DSM keep refusing.
        self.stored["device_id"] = "dev-1"
        conn = FakeConnection(FakeResponse({"success": True, "data": {"sid": "s"}}))
        self.dsm(conn=conn).login(password="hunter2", otp="123456")
        body = conn.requests[0]["body"]
        self.assertIn("otp_code=123456", body)
        self.assertNotIn("device_id", body)


class Dns(Sandbox):
    def test_a_literal_address_never_reaches_the_resolver(self):
        # Short-circuiting matters: a NAS given by IP should never touch the
        # resolver, which is where the multi-second mDNS stall lives.
        self.assertEqual(self.real_resolve_host("192.168.1.100"), "192.168.1.100")

    def test_a_failed_connection_drops_the_cached_address(self):
        # A NAS that took a new DHCP lease should cost one retry, not a
        # permanent outage until the ten-minute entry expires.
        mod._write_dns_cache({"nas.local": {"ip": "10.0.0.9",
                                            "expires": time.time() + 600}})
        conn = FakeConnection(OSError("no route"), OSError("no route"))
        dsm = mod.Dsm(dict(CONFIG))
        dsm.apis = dict(APIS)
        dsm._connect = lambda: conn
        with self.assertRaises(SystemExit):
            dsm.call("SYNO.Core.System", "info")
        self.assertNotIn("nas.local", mod._read_dns_cache())


if __name__ == "__main__":
    unittest.main(verbosity=2)
