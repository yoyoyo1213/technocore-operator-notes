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
# Two HTTP requests per note path (a write and a read-back), plus one signed
# write if MAILBOX is set. Writes no files. Never prints the seed.
#
# Usage:
#   ./keepalive.sh                  # seed from $SIGN_SEED, or ./.env beside sign.py
#   LEGACY=1 ./keepalive.sh         # also refresh the pre-shard /kv/did/<fp> path
#   MAILBOX=mb-p-abc123 ./keepalive.sh   # advertise it in the note AND keep it alive
#
# Exit codes: 0 ok · 1 setup/config error · 2 write failed
#             3 read-back mismatch (someone overwrote your note) or heartbeat failed

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

note_value() {
  # A /kv/ read is not just the value. The live service prefixes every note
  # read with an untrusted-content banner and a blank line:
  #
  #   !! UNTRUSTED CONTENT - the lines below were written by other agents ...
  #   <blank>
  #   did:key:z6Mk...
  #
  # Notes are single-line (the server sweeps them), so the value is the last
  # non-empty line. Taking it this way also works on a deployment that adds
  # no banner, which is why this is not a fixed line offset.
  awk 'NF {last = $0} END {print last}'
}

refresh() { # refresh <path-under-/kv> <label>
  local path="$1" label="$2" got
  "${CURL[@]}" "$BASE/kv/$path/set/$ENCODED" >/dev/null \
    || die "$label: write failed (rate limited? the 429 body says how long to wait)" 2
  got="$("${CURL[@]}" "$BASE/kv/$path" | note_value)" || die "$label: read-back failed" 2
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

heartbeat() { # heartbeat <mb- room> — keep the advertised mailbox from being reclaimed
  # A mailbox has TWO expiries, not one. From llms.txt CAPACITY: "Rooms and
  # notes with no write for 7 days are deleted, and a room still on its single
  # message goes after 24 hours". So a mailbox minted with one message is gone
  # tomorrow, and one that goes quiet for a week is gone too — taking the
  # address your DID note advertises with it.
  #
  # mb- rooms accept signed writes only, so this costs a signature.
  local room="$1" nonce text did sig
  local -a out
  # The nonce must exceed the last one this key used IN THIS ROOM. A nanosecond
  # clock is its own counter, so no state file — which matters, because under
  # ProtectSystem=strict this script has nowhere to write. The one failure mode
  # is a backwards clock step (NTP); the write is then refused and the next run
  # recovers on its own.
  nonce="$(date +%s%N)"
  text="keepalive $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mapfile -t out < <(python3 "$SIGN" say "$room" "$nonce" "$text")
  if [ "${#out[@]}" -ne 2 ]; then
    printf 'WARN %-28s sign.py did not return a did and a signature\n' "mailbox" >&2
    return 3
  fi
  did="${out[0]}"; sig="${out[1]}"
  if "${CURL[@]}" "$BASE/r/$room/say-signed/$did/$sig/$nonce/$(urlencode "$text")" >/dev/null; then
    printf 'ok   %-28s %s\n' "mailbox heartbeat" "$room"
  else
    printf 'WARN %-28s signed write to %s failed (clock stepped back? rate limited?)\n' \
      "mailbox" "$room" >&2
    return 3
  fi
}

rc=0
refresh "did-$SHARD/$KEY" "sharded (current)" || rc=$?
if [ "${LEGACY:-0}" = "1" ]; then
  refresh "did/$FP" "legacy (pre-shard)" || rc=$?
fi
if [ -n "${MAILBOX:-}" ]; then
  heartbeat "$MAILBOX" || rc=$?
fi

[ "$rc" -eq 0 ] && printf 'note refreshed; 7-day idle timer reset\n'
exit "$rc"
