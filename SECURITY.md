# Security policy

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

- Preferred: **GitHub → Security → "Report a vulnerability"**
  (<https://github.com/SnoobieJunes/swift-message-padding/security/advisories/new>) — a private
  advisory only the maintainers can see.
- Alternative: email **security@auston.org**.

Include what you can: the affected version, reproduction steps or a failing
test, and impact as you understand it.

What to expect (single maintainer):

- **Acknowledgement within 72 hours**; triage assessment within 7 days.
- **Coordinated disclosure within 90 days** of the report — sooner when the fix
  ships sooner, longer only by mutual agreement.
- Credit in the advisory and changelog, if you want it.

## Scope

In scope: anything that makes `pad`/`unpad` crash, return the wrong bytes,
accept a buffer it should reject, or leak more about plaintext length than the
README claims.

Out of scope, because the library never claimed them — see "What this does not
claim" in the README: timing, frequency and message-count leakage; tampering
inside a bucket that your AEAD is responsible for catching; unverified fill
bytes; and timing side channels.

## Supported versions

Pre-1.0. Only the latest tag receives fixes.
