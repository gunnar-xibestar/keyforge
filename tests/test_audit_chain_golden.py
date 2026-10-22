"""Golden characterization of the audit hash chain.

Clock, actor, and os_user are frozen so record() stores fixed bytes. The
expected hashes below are those bytes, not values recomputed by the test.
"""
import json, os, tempfile, unittest
from datetime import datetime, timezone
from unittest import mock

os.environ["KEYFORGE_PBKDF2_ITERS"] = "1000"

from keyforge import audit
from keyforge.errors import KeyForgeError
from keyforge.store import Store

GENESIS = "0" * 64
CREATE_HASH = "1c310201a4a2106019b064724341b98216f1fea8c8592c1ae7dd27ac00794f99"
VERIFY_HASH = "b0c74e05d84ac2d1f6f7d32c905e7129305efbcedcb0e696601a3e5ba028adc3"
REVOKE_HASH = "6d906d9aa470a2791cb5a6650e425e59fdb9d006ed27c86618e1b163c72a66d8"
CREATE_MAC = "75a2c00eb606b12d3c62fc5c3c77651b936343c107ddfab6351df848421328fc"
VERIFY_MAC = "c390ce49dd6b5a59be056d81ef7516b27f67a122003f0e14bb67d0506e2efff3"
REVOKE_MAC = "6b86b485a12356266a33965d833e9f58ed5f6ff887879ba36a4bb951277d9954"
META_MAC = "4188f381bad57467b4a7acd0bab5ac65b8c07601a1db8e9af9d2d72be769459d"
ADOPT_HASH = "2057ed6c27fcb130011b3042e92a11784e5253ab14a47ba72758bbe37eb72b45"
ADOPT_MAC = "cb5ca459842d41aefbb7e92c7c4a6afbe48f7bf6cc87a6f27abf1f2e9118aab3"
ADOPT_META_MAC = "03d218b4e99e28c5fd062a1ace5cc8512bd70bbabf2390979a21ec0351e04fbb"
EMPTY_ADOPT_HASH = "47f74c6cbba0dcc14e224624ed34e00fcd3da4e21ffa1ccb02b11989ba11400e"
REWRITTEN_VERIFY_HASH = "cf0200b8f2b1c6752261ae4a1d2d0cbb90b9fc9d4ba7b0f39629a1693af6f542"
REWRITTEN_REVOKE_HASH = "99793c10b6dce9563e120e44581843dd119dd2f51ab9e21adebb034979792f45"
RESEALED_META_MAC = "7250263213640ae0066bf2b1bacbbea65a7990c5fbbd353b22a18f4fd309b2af"

HMAC_KEY_REQUIRED = (
    "HMAC key required: the audit chain has MACs, but KEYFORGE_AUDIT_HMAC_KEY_FILE "
    "is unset in this process. keyforge.env has no line for it, and the shell did not "
    "export it. Setup used to rewrite that file without the line when the variable was "
    "already set in the setup process, so the next command lost it. Verify does not open "
    "the default ~/.keyforge/audit-hmac.key unless the variable names the file. "
    "The store still has mac and hmac_from from an earlier process that had the key."
)
_MAC_TAIL = (
    "The loaded HMAC key produces HMAC-SHA256 of this event's hash, and that value "
    "is not the stored mac. The hash chain matches through this event."
)


def _mac_warning(shown, span):
    return (
        f"warning: event {shown}: the computed HMAC does not match the stored mac. {span} "
        + _MAC_TAIL
    )


def _chain_events(macs=None):
    events = [
        {
            "ts": "2026-03-01T12:00:00Z", "actor": "alice", "os_user": "auditor", "os_uid": 1000,
            "action": "create", "key_id": "kid-1", "details": {"name": "n"},
            "prev_hash": GENESIS, "hash": CREATE_HASH,
        },
        {
            "ts": "2026-03-01T12:01:00Z", "actor": "alice", "os_user": "auditor", "os_uid": 1000,
            "action": "verify_ok", "key_id": "kid-1", "details": {},
            "prev_hash": CREATE_HASH, "hash": VERIFY_HASH,
        },
        {
            "ts": "2026-03-01T12:02:00Z", "actor": "alice", "os_user": "auditor", "os_uid": 1000,
            "action": "revoke", "key_id": "kid-1", "details": {"reason": "leak"},
            "prev_hash": VERIFY_HASH, "hash": REVOKE_HASH,
        },
    ]
    if macs:
        for ev, mac in zip(events, macs):
            ev["mac"] = mac
    return events


class TestAuditChainGolden(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self._saved = {}
        for key in ("KEYFORGE_AUDIT_HMAC_KEY_FILE", "SUDO_USER", "KEYFORGE_ACTOR"):
            self._saved[key] = os.environ.pop(key, None)

    def tearDown(self):
        for key, val in self._saved.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        self.d.cleanup()

    def _patch_identity(self, stamps=4):
        times = iter(datetime(2026, 3, 1, 12, i, tzinfo=timezone.utc) for i in range(stamps))
        return mock.patch.multiple(
            audit,
            now=lambda: next(times),
            actor=lambda: "alice",
            os_user=lambda: ("auditor", 1000),
        )

    def _store(self, name):
        return Store(os.path.join(self.d.name, name))

    def _keyfile(self):
        path = os.path.join(self.d.name, "hmac.key")
        with open(path, "wb") as fh:
            fh.write(b"k" * 32)
        os.chmod(path, 0o600)
        return path

    def _record_three(self, name, keyfile=None):
        st = self._store(name)
        env = {"KEYFORGE_AUDIT_HMAC_KEY_FILE": keyfile} if keyfile else {}
        with mock.patch.dict(os.environ, env):
            with self._patch_identity():
                audit.record(st, "create", "kid-1", name="n")
                audit.record(st, "verify_ok", "kid-1")
                audit.record(st, "revoke", "kid-1", reason="leak")
        return st

    def _assert_verify(self, log, meta, expected, key=None):
        result = audit.verify_chain(log, meta, key)
        if "last_event" in result:
            self.assertEqual(result.pop("last_event"), {
                "index": len(log) - 1, "fields": dict(log[-1]),
            })
        self.assertEqual(result, expected)
        return result

    def test_record_and_verify_unkeyed_chain(self):
        st = self._record_three("plain.json")
        log = _chain_events()
        self.assertEqual(st.audit_log, log)
        self.assertEqual(st.data["audit_meta"], {
            "legacy": 0, "count": 3, "head": REVOKE_HASH,
        })
        self.assertEqual(st.audit_log[0]["prev_hash"], GENESIS)
        self.assertEqual(st.audit_log[1]["prev_hash"], CREATE_HASH)
        self.assertEqual(st.audit_log[2]["prev_hash"], VERIFY_HASH)
        self._assert_verify(st.audit_log, st.data["audit_meta"], {
            "ok": True, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": False, "error": None, "index": None, "warnings": [],
            "walked": 3, "walked_last": 2, "walk_continued": False,
        })

    def test_record_and_verify_hmac_chain(self):
        kf = self._keyfile()
        st = self._record_three("hmac.json", kf)
        log = _chain_events((CREATE_MAC, VERIFY_MAC, REVOKE_MAC))
        self.assertEqual(st.audit_log, log)
        self.assertEqual(st.data["audit_meta"], {
            "legacy": 0, "count": 3, "head": REVOKE_HASH, "hmac_from": 0, "mac": META_MAC,
        })
        with open(kf, "rb") as fh:
            key = fh.read()
        self._assert_verify(st.audit_log, st.data["audit_meta"], {
            "ok": True, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": True, "error": None, "index": None, "warnings": [],
            "walked": 3, "walked_last": 2, "walk_continued": False,
        }, key=key)
        # The key file is not consulted unless the caller passes the bytes.
        self._assert_verify(st.audit_log, st.data["audit_meta"], {
            "ok": False, "checked": 0, "legacy": 0, "count": 3, "head": GENESIS,
            "mac_verified": False, "error": HMAC_KEY_REQUIRED, "index": None, "warnings": [],
        })

    def test_edited_event(self):
        st = self._record_three("edit.json")
        log = json.loads(json.dumps(st.audit_log))
        log[1]["actor"] = "eve"
        self.assertNotEqual(audit.entry_hash(log[1]), log[1]["hash"])
        self.assertEqual(audit.entry_hash(log[0]), log[0]["hash"])
        self.assertEqual(audit.entry_hash(log[2]), log[2]["hash"])
        self._assert_verify(log, st.data["audit_meta"], {
            "ok": False, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": False, "index": 1, "warnings": [],
            "error": "event 2(1): content hash mismatch (event modified)",
            "errors": ["event 2(1): content hash mismatch (event modified)"],
            "walked": 3, "walked_last": 2, "walk_continued": True,
        })

    def test_deleted_event(self):
        st = self._record_three("delete.json")
        meta = st.data["audit_meta"]
        middle = json.loads(json.dumps(st.audit_log))
        del middle[1]
        # The removed event's successor is now last, so the walk stops on it.
        # count is a second error and does not carry an index.
        self._assert_verify(middle, meta, {
            "ok": False, "checked": 2, "legacy": 0, "count": 2, "head": REVOKE_HASH,
            "mac_verified": False, "index": 1, "warnings": [],
            "error": "event 2(1): prev_hash mismatch (event removed, inserted or reordered)",
            "errors": [
                "event 2(1): prev_hash mismatch (event removed, inserted or reordered)",
                "event count 2 != recorded 3 (events added or truncated)",
            ],
            "walked": 2, "walked_last": 1, "walk_continued": False,
        })
        tail = json.loads(json.dumps(st.audit_log))
        tail.pop()
        # Count and head notes do not record an index.
        self._assert_verify(tail, meta, {
            "ok": False, "checked": 2, "legacy": 0, "count": 2, "head": VERIFY_HASH,
            "mac_verified": False, "error": "event count 2 != recorded 3 (events added or truncated)",
            "errors": [
                "event count 2 != recorded 3 (events added or truncated)",
                "head hash does not match metadata",
            ],
            "index": None, "warnings": [],
            "walked": 2, "walked_last": 1, "walk_continued": False,
        })

    def test_reordered_event(self):
        st = self._record_three("reorder.json")
        log = json.loads(json.dumps(st.audit_log))
        log[0], log[1] = log[1], log[0]
        for ev in log:
            self.assertEqual(audit.entry_hash(ev), ev["hash"])
        mismatch = "prev_hash mismatch (event removed, inserted or reordered)"
        self._assert_verify(log, st.data["audit_meta"], {
            "ok": False, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": False, "index": 0, "warnings": [],
            "error": f"event 1(0): {mismatch}",
            "errors": [
                f"event 1(0): {mismatch}",
                f"event 2(1): {mismatch}",
                f"event 3(2): {mismatch}",
            ],
            "walked": 3, "walked_last": 2, "walk_continued": True,
        })

    def test_bad_mac(self):
        kf = self._keyfile()
        st = self._record_three("bad-mac.json", kf)
        with open(kf, "rb") as fh:
            key = fh.read()
        meta = json.loads(json.dumps(st.data["audit_meta"]))

        replaced = json.loads(json.dumps(st.audit_log))
        replaced[1]["mac"] = "0" * 64
        # A present-but-wrong MAC is a warning. ok stays true, and mac_verified
        # stays true because the other event MACs still match.
        self._assert_verify(replaced, meta, {
            "ok": True, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": True, "error": None, "index": None,
            "warnings": [_mac_warning(
                "2(1)",
                "HMAC VALID for events 1(0) through 1(0). HMAC INVALID for event 2(1).",
            )],
            "walked": 3, "walked_last": 2, "walk_continued": False,
        }, key=key)

        missing = json.loads(json.dumps(st.audit_log))
        missing[1].pop("mac")
        missing_mac = (
            "event 2(1): MAC missing.\n"
            "\n"
            "chain: hmac_from is 1(0), so this event must carry a MAC from the loaded HMAC key.\n"
            "\n"
            "hash: the stored hash equals SHA-256 of this event with hash and mac removed, "
            "and prev_hash links to the previous event.\n"
            "\n"
            "mac: there is no mac field.\n"
            "\n"
            "write: none recorded\n"
            "\n"
            "event:\n"
            "  ts: 2026-03-01T12:01:00Z\n"
            "  action: verify_ok\n"
            "  key_id: kid-1\n"
            "  actor: alice\n"
            "  os_user: auditor"
        )
        self._assert_verify(missing, meta, {
            "ok": False, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": False, "index": 1, "warnings": [],
            "error": missing_mac,
            "errors": [missing_mac],
            "walked": 3, "walked_last": 2, "walk_continued": True,
        }, key=key)

        recorded = json.loads(json.dumps(missing))
        recorded[1]["hmac_error"] = "disk full"
        # hmac_error is part of the hashed body, so the same event fails the content
        # hash and then still emits MAC missing. That second text says the stored
        # hash matches, which the first error has already contradicted, and it
        # quotes the write-time hmac_error.
        failed = audit.verify_chain(recorded, meta, key)
        self.assertFalse(failed["ok"])
        self.assertEqual(failed["errors"][0], "event 2(1): content hash mismatch (event modified)")
        self.assertEqual(failed["index"], 1)
        self.assertIn("write: disk full", failed["errors"][1])
        self.assertIn("the stored hash equals SHA-256", failed["errors"][1])

        all_bad = json.loads(json.dumps(st.audit_log))
        for ev in all_bad:
            ev["mac"] = "11" * 32
        # Every event MAC is wrong and the metadata MAC still matches: ok stays
        # true, mac_verified is false. matched_through never advances, so each
        # warning says this is the first event that must have a MAC.
        first = "HMAC INVALID for event {shown}. This is the first event that must have a MAC."
        self._assert_verify(all_bad, meta, {
            "ok": True, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": False, "error": None, "index": None,
            "warnings": [
                _mac_warning("1(0)", first.format(shown="1(0)")),
                _mac_warning("2(1)", first.format(shown="2(1)")),
                _mac_warning("3(2)", first.format(shown="3(2)")),
            ],
            "walked": 3, "walked_last": 2, "walk_continued": False,
        }, key=key)

        stale_meta = json.loads(json.dumps(meta))
        stale_meta["mac"] = "0" * 64
        both = audit.verify_chain(all_bad, stale_meta, key)
        self.assertFalse(both["ok"])
        self.assertEqual(both["error"], "audit metadata MAC invalid")
        self.assertEqual(both["index"], None)
        self.assertEqual(len(both["warnings"]), 3)

    def test_tail_deletion_healed_by_next_record(self):
        st = self._record_three("heal.json")
        tip = st.audit_log[1]["hash"]
        st.audit_log.pop()
        broken = audit.verify_chain(st.audit_log, st.data["audit_meta"])
        self.assertFalse(broken["ok"])
        self.assertIsNone(broken["index"])
        with self._patch_identity():
            audit.record(st, "export", None, n=1)
        healed = audit.verify_chain(st.audit_log, st.data["audit_meta"])
        self.assertTrue(healed["ok"], healed)
        self.assertEqual([e["action"] for e in st.audit_log], ["create", "verify_ok", "export"])
        self.assertEqual(st.audit_log[-1]["prev_hash"], tip)
        self.assertEqual(st.data["audit_meta"]["count"], 3)
        self.assertEqual(st.data["audit_meta"]["head"], st.audit_log[-1]["hash"])

        kf = self._keyfile()
        keyed = self._record_three("heal-mac.json", kf)
        with open(kf, "rb") as fh:
            key = fh.read()
        keyed.audit_log.pop()
        self.assertFalse(audit.verify_chain(keyed.audit_log, keyed.data["audit_meta"], key)["ok"])
        with mock.patch.dict(os.environ, {"KEYFORGE_AUDIT_HMAC_KEY_FILE": kf}):
            with self._patch_identity():
                audit.record(keyed, "export", None, n=1)
        again = audit.verify_chain(keyed.audit_log, keyed.data["audit_meta"], key)
        self.assertTrue(again["ok"], again)
        self.assertTrue(again["mac_verified"])
        self.assertEqual([e["action"] for e in keyed.audit_log], ["create", "verify_ok", "export"])
        self.assertIn("mac", keyed.audit_log[-1])

        # A missing middle event is not rewritten into a valid chain.
        middle = self._record_three("heal-middle.json")
        del middle.audit_log[1]
        with self._patch_identity():
            audit.record(middle, "export")
        left = audit.verify_chain(middle.audit_log, middle.data["audit_meta"])
        self.assertFalse(left["ok"])
        self.assertEqual(left["errors"], [
            "event 2(1): prev_hash mismatch (event removed, inserted or reordered)",
        ])
        self.assertEqual(middle.data["audit_meta"]["count"], len(middle.audit_log))
        self.assertEqual(left["index"], 1)
        self.assertTrue(left["walk_continued"])

    def test_adopt_legacy(self):
        legacy = [
            {"ts": "2026-01-01T00:00:00Z", "actor": "x", "os_user": "x", "os_uid": 1,
             "action": "create", "key_id": "kid-1", "details": {"name": "old"}},
            {"ts": "2026-01-02T00:00:00Z", "actor": "x", "os_user": "x", "os_uid": 1,
             "action": "revoke", "key_id": "kid-1", "details": {"reason": "old"}},
        ]
        st = self._store("legacy.json")
        st.data["audit"] = json.loads(json.dumps(legacy))
        st.data.pop("audit_meta")
        with self._patch_identity():
            ev = audit.adopt_legacy(st)
        self.assertEqual(ev, {
            "ts": "2026-03-01T12:00:00Z", "actor": "alice", "os_user": "auditor", "os_uid": 1000,
            "action": "audit_adopt_legacy", "key_id": None, "details": {"legacy": 2},
            "prev_hash": GENESIS, "hash": ADOPT_HASH,
        })
        self.assertIs(st.audit_log[-1], ev)
        self.assertEqual(st.audit_log[:2], legacy)
        self.assertEqual(st.data["audit_meta"], {
            "legacy": 2, "count": 3, "head": ADOPT_HASH,
        })
        self._assert_verify(st.audit_log, st.data["audit_meta"], {
            "ok": True, "checked": 1, "legacy": 2, "count": 3, "head": ADOPT_HASH,
            "mac_verified": False, "error": None, "index": None, "warnings": [],
            "walked": 3, "walked_last": 2, "walk_continued": False,
        })

        st.audit_log[0]["action"] = "tampered"
        still = audit.verify_chain(st.audit_log, st.data["audit_meta"])
        self.assertTrue(still["ok"], still)
        self.assertEqual(still["legacy"], 2)
        self.assertEqual(still["checked"], 1)

        st.audit_log[0]["hash"] = "ab" * 32
        self._assert_verify(st.audit_log, st.data["audit_meta"], {
            "ok": False, "checked": 1, "legacy": 1, "count": 3, "head": ADOPT_HASH,
            "mac_verified": False, "index": 0, "warnings": [],
            "error": "event 1(0) is chained but recorded as legacy",
            "errors": ["event 1(0) is chained but recorded as legacy"],
            "walked": 3, "walked_last": 2, "walk_continued": True,
        })

        fresh = self._store("fresh.json")
        with self.assertRaises(KeyForgeError) as cm:
            audit.adopt_legacy(fresh)
        self.assertEqual(str(cm.exception), "audit chain already initialized")

        chained = self._record_three("chained.json")
        chained.data.pop("audit_meta")
        with self.assertRaises(KeyForgeError) as cm:
            audit.adopt_legacy(chained)
        self.assertEqual(
            str(cm.exception),
            "log contains chained events but no metadata: refusing to adopt (possible tampering)",
        )
        self.assertNotIn("audit_meta", chained.data)

        empty = self._store("empty.json")
        empty.data.pop("audit_meta")
        with self._patch_identity():
            audit.adopt_legacy(empty)
        self.assertEqual(empty.data["audit_meta"], {
            "legacy": 0, "count": 1, "head": EMPTY_ADOPT_HASH,
        })
        self.assertEqual(empty.audit_log, [{
            "ts": "2026-03-01T12:00:00Z", "actor": "alice", "os_user": "auditor", "os_uid": 1000,
            "action": "audit_adopt_legacy", "key_id": None, "details": {"legacy": 0},
            "prev_hash": GENESIS, "hash": EMPTY_ADOPT_HASH,
        }])
        self.assertTrue(audit.verify_chain(empty.audit_log, empty.data["audit_meta"])["ok"])

        kf = self._keyfile()
        adopted = self._store("legacy-mac.json")
        adopted.data["audit"] = json.loads(json.dumps(legacy))
        adopted.data.pop("audit_meta")
        with mock.patch.dict(os.environ, {"KEYFORGE_AUDIT_HMAC_KEY_FILE": kf}):
            with self._patch_identity():
                ev = audit.adopt_legacy(adopted)
        self.assertEqual(ev["hash"], ADOPT_HASH)
        self.assertEqual(ev["mac"], ADOPT_MAC)
        self.assertNotIn("mac", adopted.audit_log[0])
        self.assertNotIn("hash", adopted.audit_log[0])
        self.assertEqual(adopted.data["audit_meta"], {
            "legacy": 2, "count": 3, "head": ADOPT_HASH, "hmac_from": 2, "mac": ADOPT_META_MAC,
        })
        with open(kf, "rb") as fh:
            key = fh.read()
        sealed = audit.verify_chain(adopted.audit_log, adopted.data["audit_meta"], key)
        self.assertTrue(sealed["ok"], sealed)
        self.assertTrue(sealed["mac_verified"])
        self.assertEqual(sealed["legacy"], 2)
        self.assertEqual(sealed["checked"], 1)

    def test_reseal_metadata_mac(self):
        kf = self._keyfile()
        st = self._record_three("reseal.json", kf)
        with open(kf, "rb") as fh:
            key = fh.read()
        meta = st.data["audit_meta"]
        self.assertFalse(audit.reseal_metadata_mac(st, None))
        self.assertFalse(audit.reseal_metadata_mac(st, b""))
        self.assertEqual(meta["mac"], META_MAC)

        meta["mac"] = "0" * 64
        stale = audit.verify_chain(st.audit_log, meta, key)
        self.assertTrue(stale["ok"], stale)
        self.assertTrue(stale["meta_mac_stale"])
        self.assertFalse(stale["mac_verified"])
        self.assertEqual(stale["warnings"], [])
        self.assertTrue(audit.reseal_metadata_mac(st, key))
        self.assertEqual(meta["mac"], META_MAC)
        self.assertFalse(audit.reseal_metadata_mac(st, key))
        resealed = audit.verify_chain(st.audit_log, meta, key)
        self.assertTrue(resealed["ok"], resealed)
        self.assertTrue(resealed["mac_verified"])
        self.assertNotIn("meta_mac_stale", resealed)

        saved = meta["mac"]
        meta["mac"] = "0" * 64
        st.audit_log[1]["actor"] = "eve"
        self.assertFalse(audit.reseal_metadata_mac(st, key))
        self.assertEqual(meta["mac"], "0" * 64)
        st.audit_log[1]["actor"] = "alice"
        meta["mac"] = saved

        bare = self._store("no-meta.json")
        bare.data.pop("audit_meta")
        self.assertFalse(audit.reseal_metadata_mac(bare, key))
        bare.data["audit_meta"] = ["nope"]
        self.assertFalse(audit.reseal_metadata_mac(bare, key))
        self.assertEqual(bare.data["audit_meta"], ["nope"])

        unkeyed = self._record_three("unkeyed.json")
        before = json.loads(json.dumps(unkeyed.data["audit_meta"]))
        self.assertFalse(audit.reseal_metadata_mac(unkeyed, key))
        self.assertEqual(unkeyed.data["audit_meta"], before)
        self._assert_verify(unkeyed.audit_log, unkeyed.data["audit_meta"], {
            "ok": False, "checked": 3, "legacy": 0, "count": 3, "head": REVOKE_HASH,
            "mac_verified": False, "index": None, "warnings": [],
            "error": "audit metadata MAC invalid",
            "errors": ["audit metadata MAC invalid"],
            "walked": 3, "walked_last": 2, "walk_continued": False,
        }, key=key)

        # Rewrite the hash chain from the second event and point head at the new
        # tip, leaving the original event MACs in place. The first MAC still
        # matches, so verify stays ok and reseal writes a metadata MAC over the
        # rewritten tip. Later event MACs are left wrong, and mac_verified becomes true.
        rewritten = self._record_three("rewrite.json", kf)
        log = rewritten.audit_log
        log[1]["actor"] = "eve"
        log[1]["hash"] = audit.entry_hash(log[1])
        log[2]["prev_hash"] = log[1]["hash"]
        log[2]["hash"] = audit.entry_hash(log[2])
        self.assertEqual(log[1]["hash"], REWRITTEN_VERIFY_HASH)
        self.assertEqual(log[2]["hash"], REWRITTEN_REVOKE_HASH)
        self.assertEqual(log[1]["mac"], VERIFY_MAC)
        self.assertEqual(log[2]["mac"], REVOKE_MAC)
        rewritten.data["audit_meta"]["head"] = log[2]["hash"]
        before_macs = (log[1]["mac"], log[2]["mac"])
        warned = audit.verify_chain(log, rewritten.data["audit_meta"], key)
        self.assertTrue(warned["ok"], warned)
        self.assertFalse(warned["mac_verified"])
        self.assertTrue(warned["meta_mac_stale"])
        self.assertEqual(warned["warnings"], [
            _mac_warning(
                "2(1)",
                "HMAC VALID for events 1(0) through 1(0). HMAC INVALID for event 2(1).",
            ),
            _mac_warning("3(2)", "HMAC INVALID for event 3(2)."),
        ])
        self.assertTrue(audit.reseal_metadata_mac(rewritten, key))
        self.assertEqual(rewritten.data["audit_meta"]["mac"], RESEALED_META_MAC)
        self.assertEqual((log[1]["mac"], log[2]["mac"]), before_macs)
        after = audit.verify_chain(log, rewritten.data["audit_meta"], key)
        self.assertTrue(after["ok"], after)
        self.assertTrue(after["mac_verified"])
        self.assertNotIn("meta_mac_stale", after)
        self.assertEqual(len(after["warnings"]), 2)


if __name__ == "__main__":
    unittest.main()
