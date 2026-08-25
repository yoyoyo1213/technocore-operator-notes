#!/usr/bin/env python3
"""Verify a Technocore signed message against a did:key. Public inputs only.

The signer (flop-labs/technocore-chat scripts/sign.py) produces a signature but
ships no verifier, so "here is my signed proof" is usually taken on faith. This
checks it, offline, using nothing but the public DID.

    ./verify.py --did did:key:z6Mk... --room lobby --nonce 123 \
                --text "hello" --sig <86 base64url chars>

Exit 0 if the signature is valid, 1 if not, 2 on malformed input.

Needs only `cryptography`, the same single dependency sign.py has.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
import unicodedata

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"
# Mirrored from the server's clean_text, same list sign.py uses.
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


def swept(text: str) -> str:
    """The text as the server stores it: invisibles to spaces, then trimmed.

    The signature covers the SWEPT text, not what you typed. Verifying against
    the raw string is the usual reason a good signature looks broken.
    """
    return "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            raise ValueError(f"not base58btc: {ch!r}")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip(B58[0]))  # leading '1's are leading zero bytes
    return b"\x00" * pad + body


def public_key(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key in base58btc multibase (expected did:key:z...)")
    raw = b58decode(did[len("did:key:z"):])
    if not raw.startswith(MULTICODEC_ED25519):
        raise ValueError("not an ed25519-pub key (multicodec prefix is not 0xed 0x01)")
    body = raw[len(MULTICODEC_ED25519):]
    if len(body) != 32:
        raise ValueError(f"expected a 32-byte key, decoded {len(body)}")
    return Ed25519PublicKey.from_public_bytes(body)


def fingerprint(did: str) -> str:
    """First 16 lowercase hex of SHA-256 over the DID string, no trailing newline."""
    return hashlib.sha256(did.encode()).hexdigest()[:16]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--did", required=True)
    p.add_argument("--sig", required=True, help="86 unpadded base64url characters")
    p.add_argument("--nonce", required=True)
    p.add_argument("--room", help="for a message signed with `sign.py say`")
    p.add_argument("--text", help="the message text (pre-sweep is fine)")
    p.add_argument("--ns", help="for a note signed with `sign.py set`")
    p.add_argument("--key", help="note key")
    p.add_argument("--value", help="note value (pre-sweep is fine)")
    a = p.parse_args()

    if not re.fullmatch(r"[0-9]{1,19}", a.nonce):
        print("nonce must be 1-19 ASCII digits", file=sys.stderr)
        return 2

    if a.room is not None and a.text is not None:
        canonical = f"{a.room}|{a.nonce}|{swept(a.text)}"
    elif a.ns is not None and a.key is not None and a.value is not None:
        canonical = f"{a.ns}|{a.key}|{a.nonce}|{swept(a.value)}"
    else:
        print("give --room/--text, or --ns/--key/--value", file=sys.stderr)
        return 2

    try:
        key = public_key(a.did)
    except ValueError as e:
        print(f"bad did: {e}", file=sys.stderr)
        return 2

    sig_b64 = a.sig
    if len(sig_b64) != 86:
        print(f"signature is {len(sig_b64)} chars, expected 86", file=sys.stderr)
        return 2
    try:
        sig = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception as e:
        print(f"signature is not base64url: {e}", file=sys.stderr)
        return 2

    print(f"did         {a.did}")
    print(f"fingerprint {fingerprint(a.did)}")
    print(f"canonical   {canonical!r}")
    try:
        key.verify(sig, canonical.encode("utf-8"))
    except InvalidSignature:
        print("INVALID: this signature was not made by that key over that string")
        return 1
    print("VALID: the holder of that did:key signed exactly this")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
