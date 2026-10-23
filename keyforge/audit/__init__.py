"""Append-only (mock) audit log stored alongside keys.

Integrity
- Every event carries ``prev_hash`` (previous event's hash, or GENESIS) and ``hash`` = SHA-256 over
  the canonical JSON bytes of the event minus ``hash``/``mac`` (sorted keys, compact separators,
  no ``default=str``: events are normalized to plain JSON before hashing, so the hashed bytes are
  exactly what round-trips through the store).
- ``store.data["audit_meta"]`` holds ``legacy`` (events that pre-date chaining, fixed when chaining
  starts), ``count`` and ``head``. Verification fails if these disagree with the log, so stripping
  ``hash``/``prev_hash`` from events or truncating the tail is detected.
- Optional HMAC: if ``$KEYFORGE_AUDIT_HMAC_KEY_FILE`` names a file (kept outside the store), each
  new event gets ``mac`` = HMAC-SHA256(key, hash) and the metadata is MAC'd too, so someone who can
  edit the store but not read the key cannot rebuild a valid chain.

Attribution: KEYFORGE_ACTOR and SUDO_USER are *claims* (env vars); ``os_user``/``os_uid`` come
from the process uid and are what to trust.
"""
from __future__ import annotations
import getpass, hashlib, hmac, json, os, sys
from ..errors import KeyForgeError
from . import chain, format, log

iso = log.iso
now = log.now
parse_iso = log.parse_iso
GENESIS = chain.GENESIS
canonical = chain.canonical
os_user = log.os_user
actor = log.actor
hmac_key = chain.hmac_key
entry_hash = chain.entry_hash
_mac = chain._mac
_shown = chain._shown
_event_facts = chain._event_facts
_event_mac_error = chain._event_mac_error
_event_mac_warning = chain._event_mac_warning
_meta_msg = chain._meta_msg
record = log.record
_record_unchained = log._record_unchained
_chain_expects_hmac = chain._chain_expects_hmac
verify_chain = chain.verify_chain
walk_movement = format.walk_movement
walk_line = format.walk_line
last_event_lines = format.last_event_lines
reseal_metadata_mac = chain.reseal_metadata_mac
_check = format._check
_event_date = format._event_date
_hmac_key_missing_message = chain._hmac_key_missing_message
_event_reason = format._event_reason
key_event_match = format.key_event_match
verify_report = format.verify_report
adopt_legacy = log.adopt_legacy
query = log.query

__all__ = [
    "annotations",
    "getpass", "hashlib", "hmac", "json", "os", "sys",
    "KeyForgeError",
    "iso", "now", "parse_iso",
    "GENESIS", "canonical", "os_user", "actor", "hmac_key", "entry_hash",
    "record", "verify_chain", "walk_movement", "walk_line", "last_event_lines",
    "reseal_metadata_mac", "key_event_match", "verify_report", "adopt_legacy", "query",
]
