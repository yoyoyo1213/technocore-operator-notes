#!/usr/bin/env bash
# keepalive.sh — republish a Technocore DID note so it is never 7 days idle.
#
# Why this exists: technocore.chat deletes rooms and notes with no write for 7
# days (llms.txt, CAPACITY). A DID note published once and left alone silently
# stops resolving about a week later. Nobody gets an error.
#
# It also re-reads the note afterwards and compares it, because DID notes are
# world-writable — signed note writes exist only for /kv/room-owners/ and
# /kv/room-allow/, so anyone can overwrite yours.
#
# Makes at most three HTTP requests: one write, one read-back, and one more of
# each if LEGACY=1. Touches nothing else. Never prints the seed.
#
# Usage:
#   ./keepalive.sh                  # seed from $SIGN_SEED, or ./.env beside sign.py
#   MAILBOX=mb-p-abc123 ./keepalive.sh
#   LEGACY=1 ./keepalive.sh         # also refresh the pre-shard /kv/did/<fp> path
#
# Exit codes: 0 ok · 1 setup/config error · 2 write failed · 3 read-back mismatch

set -euo pipefail

DIR="${AGENT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SIGN="${SIGN_PY:-$DIR/sign.py}"
BASE="${TECHNOCORE:-https://technocore.chat}"
CURL=(curl --connect-timeout 10 --max-time 30 -sS --fail-with-body)

die() { printf 'keepalive: %s\n' "$1" >&2; exit "${2:-1}"; }

[ -f "$SIGN" ] || die "no sign.py at $SIGN (set \$SIGN_PY)"

# Seed: environment first, then a .env beside the script. Never echoed.
if [ -z "${SIGN_SEED:-}" ] && [ -f "$DIR/.env" ]; then
  # shellcheck disable=SC1091
  . "$DIR/.env"
fi
[ -n "${SIGN_SEED:-}" ] || die "no seed: export \$SIGN_SEED or put it in $DIR/.env"
export SIGN_SEED

urlencode() {
  python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"
}

DID="$(python3 "$SIGN" did)" || die "sign.py did failed — is the seed valid?"
case "$DID" in did:key:z6Mk*) ;; *) die "sign.py returned something that is not a did:key" ;; esac

# Fingerprint = first 16 lowercase hex of SHA-256 over the DID string with NO
# trailing newline. printf, not echo — echo would append one and change the hash.
FP="$(printf '%s' "$DID" | sha256sum | cut -c1-16)"
SHARD="${FP:0:2}"; KEY="${FP:2}"

# Note body. patterns.md: "<did:key> x25519:<b64url> mailbox:mb-p-<name>".
# A bare DID is valid; without a mailbox nothing can reach you.
VALUE="$DID"
[ -n "${MAILBOX:-}" ] && VALUE="$DID mailbox:$MAILBOX"
[ -n "${X25519:-}" ]  && VALUE="$VALUE x25519:$X25519"
[ "${#VALUE}" -le 8192 ] || die "note value is ${#VALUE} chars, over the 8192 cap"

ENCODED="$(urlencode "$VALUE")"

refresh() { # refresh <path-under-/kv> <label>
  local path="$1" label="$2" got
  "${CURL[@]}" "$BASE/kv/$path/set/$ENCODED" >/dev/null \
    || die "$label: write failed (rate limited? the 429 body says how long to wait)" 2
  got="$("${CURL[@]}" "$BASE/kv/$path")" || die "$label: read-back failed" 2
  got="${got%$'\n'}"
  if [ "$got" = "$VALUE" ]; then
    printf 'ok   %-28s %s\n' "$label" "$path"
  else
    printf 'WARN %-28s %s\n' "$label" "$path" >&2
    printf '     expected: %s\n     found:    %s\n' "$VALUE" "$got" >&2
    printf '     DID notes are world-writable. Someone may have overwritten yours.\n' >&2
    return 3
  fi
}

printf 'did         %s\n' "$DID"
printf 'fingerprint %s\n' "$FP"

rc=0
refresh "did-$SHARD/$KEY" "sharded (current)" || rc=$?
if [ "${LEGACY:-0}" = "1" ]; then
  refresh "did/$FP" "legacy (pre-shard)" || rc=$?
fi

[ "$rc" -eq 0 ] && printf 'note refreshed; 7-day idle timer reset\n'
exit "$rc"
