# swift-message-padding

**Fixed-size bucket padding for encrypted messages.** Encryption hides *what*
you said. It does not hide *how much* you said — this narrows that leak to one
of five buckets.

[![CI](https://github.com/SnoobieJunes/swift-message-padding/actions/workflows/ci.yml/badge.svg)](https://github.com/SnoobieJunes/swift-message-padding/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![swift-tools 6.0+](https://img.shields.io/badge/swift--tools-6.0%2B-orange.svg)](https://swift.org)

- **Zero dependencies.** Pure Foundation, one file.
- **Zero opinions about your crypto.** It hands you bytes to seal and takes
  bytes back after you open them.
- **Linux and Apple platforms.**

---

## Why this exists

Your messenger encrypts what you write, so whoever carries it cannot read it.
They can still see how *big* each message was — and size alone says a lot.

A one-word reply looks nothing like a pasted document. Someone watching the
sizes go past can tell an "ok" from a paragraph, spot the moment a quiet
conversation turns into a long one, and often work out which of a few
predictable messages you just sent. None of that requires breaking any
encryption. It is the part encryption was never covering.

This library rounds every message up to one of a few standard sizes *before* it
gets encrypted, so a "yes" and a two-sentence reply leave at the same size and
become indistinguishable from each other. You pay for that in wasted bandwidth,
and you pay honestly — see [what it costs](#what-it-costs).

**Use it if** you are building something where the traffic itself is sensitive:
a messenger, a client talking to a relay it does not trust, anything where
someone on the network can watch your packets and would learn something from
their sizes. **Skip it if** nobody hostile is in a position to see your message
sizes in the first place — a server you already trust with the contents learns
nothing new from their lengths.

## The problem

An observer who can see ciphertext lengths — your relay, a network operator,
anyone on the path — learns a surprising amount without breaking anything:

| They see | They infer |
|---|---|
| 12-byte ciphertext | probably "ok" / "yes" / an ack |
| 4 KB ciphertext | a long message, a paste, a document |
| a 60-byte reply to a 3 KB message | a short answer to a long question |
| lengths matching a known template | *which* canned message you sent |

Length is metadata that survives end-to-end encryption, and it is what traffic
analysis is built on.

## The fix

Round every plaintext up to one of a small ladder of sizes before you encrypt.
All messages in a bucket become indistinguishable by length.

```swift
import CryptoKit
import MessagePadding

// Before your AEAD:
let padded = try Padding.pad(Data("hello".utf8))   // 260 bytes (256 bucket + 4)
let sealed = try AES.GCM.seal(padded, using: key, authenticating: ad)

// After your AEAD opens and authenticates:
let plaintext = try Padding.unpad(opened)          // back to "hello"
```

`pad` and `unpad` are the whole surface; `bucket(for:)` and the bucket
constants are public for callers that need them.

Default ladder: `256, 1024, 4096, 16384, 65536`. Five distinct sizes, so a
length observation carries **at most log2(5) ≈ 2.3 bits**, down from at most
~16 for a raw length in the same range. (Both are upper bounds, reached only if
every size is equally likely; real traffic leaks less than its bound, before
and after.) Powers of four rather than two, because fewer buckets leak less and
the wasted bytes are cheap for text.

Bring your own ladder if your traffic looks different:

```swift
let buckets = [64, 512, 4096]
let padded = try Padding.pad(plaintext, buckets: buckets)
let back = try Padding.unpad(padded, buckets: buckets)
```

The ladder is part of your wire format. Both ends must agree on it, and it must
not vary per-message with anything secret — a ladder chosen from the content is
a side channel that undoes the padding.

## Wire format

```
u32be(plaintext length) || plaintext || 0x00 … to the bucket boundary
```

The 4-byte length prefix sits **outside** the bucket accounting, so a plaintext
of exactly 65536 bytes still fits the largest bucket. Padded size for bucket `B`
is therefore `B + 4`.

What actually hits the wire depends on your AEAD framing — AES-GCM adds a 16-byte
tag, and CryptoKit's combined representation also carries a 12-byte nonce, giving
`B + 32`. The overhead is constant across buckets, which is the only part that
matters here.

Deterministic and zero-filled — no randomness, nothing to seed, nothing to
reproduce in a test.

## What it costs

Bandwidth, and not a small amount. The padding is the cost; there is no version
of this that is free.

| Plaintext | On the wire (pre-AEAD) | Cost |
|---|---|---|
| 1 byte | 260 | 260× |
| "hello" (5 B) | 260 | 52× |
| 250 B | 260 | 1.04× |
| 257 B | 1028 | 4.0× |
| 4097 B | 16388 | 4.0× |

Small messages pay enormously in relative terms — that is precisely what buys
the indistinguishability, since a 1-byte message that stayed small would still
be recognisably a 1-byte message. Above the first bucket the worst case is a
whisker over 4×, landing just past a boundary. Typical chat traffic sits well
under that, because most messages are far below 256 bytes and pay a fixed 260.

If 4× is too much for your traffic, use a denser ladder — you are trading
bandwidth for bits of leakage, and the knob is yours.

## Three things worth knowing

**Pad before you encrypt, not after.** Padding ciphertext pads the wrong thing;
the length you are hiding is the plaintext's.

**Never compress after padding.** Compression collapses the zero fill and hands
back the original length, undoing the entire library. If your transport
compresses, either turn it off for this payload or compress *before* padding —
and know that compressing plaintext before encryption has its own well-known
hazards (CRIME, BREACH).

**Oversize input is refused, not truncated.** Anything past the largest bucket
throws. Chunk it yourself — silently splitting or cutting here would hide a
data-loss bug behind a convenience.

## What this does not claim

Calibration matters more than marketing, so here is the honest boundary.

- **It hides one message's length. Nothing else.** Timing, frequency, and the
  number of messages you send all still leak, and those are often enough on
  their own. A 1 MB file chunked into 16 KB pieces reveals its size in the
  count of chunks no matter how each chunk is padded.
- **`unpad` is not an authentication check.** It rejects buffers whose declared
  length does not match the bucket actually present, which stops a *truncated*
  buffer from decoding to a shorter plaintext. But rewriting the length to
  another value inside the same bucket is accepted and returns a prefix of the
  plaintext. That is a shape check, not integrity. Authenticate with your AEAD
  first, then unpad.
- **Fill bytes are not inspected.** A buffer with the right shape and corrupt
  fill passes. A malicious *sender* can therefore use the fill as a covert
  channel — though a malicious sender has plenty of those regardless.
- **Not constant-time.** All failures do throw the same single error, so there
  is nothing for a caller to distinguish, but the code is not written to a
  timing-side-channel standard and should not be relied on as if it were.
- **Fixed buckets are not the last word.** Schemes like PADME bound overhead
  more tightly, and no padding scheme defeats a determined traffic-analysis
  adversary who also has timing and volume. This is a large, cheap improvement
  over sending raw lengths — not a solution to traffic analysis.
- **Not audited.** One reviewer, an adversarial test suite, and code short
  enough to read in full. Judge it on that.

## Installation

```swift
.package(url: "https://github.com/SnoobieJunes/swift-message-padding.git", from: "0.1.0")
```

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "MessagePadding", package: "swift-message-padding")
])
```

## Testing

```bash
swift test
```

No simulator, no network, no clock.

CI runs the suite on macOS (arm64) and Linux (x86-64), and compiles the library
for watchOS/arm64_32 — the one supported platform where `Int` is 32 bits wide,
which is where length arithmetic on a hostile buffer has to be right.

Also verified locally: macOS 26 / Swift 6.3.3 and Linux aarch64 / Swift 6.2.4
in Docker — 16 tests, both.

## Viae

**Viae** — after the roads of the Roman Empire — is a family of small,
zero-dependency, adversarially tested Swift primitives: well-paved routes for
data moving between machines that do not trust each other. Each one does a
single thing, holds no opinion about the rest of your stack, and is short
enough to read end to end before you depend on it.

- **swift-message-padding** — this package. Stops ciphertext length from
  leaking message length.
- **untrusted-data-envelope** — structural prompt-injection containment.
  *(not yet published)*
- **swift-credential-redactor** — secret-shape scrubbing for agent output.
  *(not yet published)*

## License

[Apache-2.0](LICENSE).
