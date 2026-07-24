# swift-message-padding

**Fixed-size bucket padding for encrypted messages.** Encryption hides *what*
you said. It does not hide *how much* you said — this narrows that leak to one
of five buckets.

[![CI](https://github.com/SnoobieJunes/swift-message-padding/actions/workflows/ci.yml/badge.svg)](https://github.com/SnoobieJunes/swift-message-padding/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Swift 6](https://img.shields.io/badge/swift-6.0-orange.svg)](https://swift.org)

- **Zero dependencies.** Pure Foundation, one file.
- **Zero opinions about your crypto.** It hands you bytes to seal and takes
  bytes back after you open them.
- **Linux and Apple platforms.**

---

## The problem

An observer who can see ciphertext lengths — your relay, a network operator,
anyone on the path — learns a surprising amount without breaking anything:

| They see | They infer |
|---|---|
| 12-byte ciphertext | probably "ok" / "yes" / an ack |
| 4 KB ciphertext | a long message, a paste, a document |
| a 60-byte reply to a 3 KB message | a short answer to a long question |
| lengths matching a known template | *which* canned message you sent |

Length is metadata, and metadata is what survives end-to-end encryption. It is
also what traffic analysis is built on.

## The fix

Round every plaintext up to one of a small ladder of sizes before you encrypt.
All messages in a bucket become indistinguishable by length.

```swift
import MessagePadding

// Before your AEAD:
let padded = try Padding.pad(Data("hello".utf8))   // 260 bytes (256 bucket + 4)
let sealed = try AES.GCM.seal(padded, using: key, authenticating: ad)

// After your AEAD opens and authenticates:
let plaintext = try Padding.unpad(opened)          // back to "hello"
```

`pad` and `unpad` are the whole surface; `bucket(for:)` and the bucket
constants are public for callers that need them.

Default ladder: `256, 1024, 4096, 16384, 65536`. A length observation now
carries ~2.3 bits instead of ~16. Powers of four rather than two, because fewer
buckets leak less and the wasted bytes are cheap for text.

Bring your own ladder if your traffic looks different:

```swift
let buckets = [64, 512, 4096]
let padded = try Padding.pad(plaintext, buckets: buckets)
let back = try Padding.unpad(padded, buckets: buckets)
```

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

## Three things worth knowing

**Pad before you encrypt, not after.** Padding ciphertext pads the wrong thing;
the length you are hiding is the plaintext's.

**`unpad` is not an authentication check.** It rejects malformed and
length/bucket-mismatched buffers, which stops a truncated buffer from quietly
decoding to a shorter attacker-chosen plaintext. That is a correctness backstop,
not integrity. Authenticate with your AEAD first, then unpad.

**Oversize input is refused, not truncated.** Anything past the largest bucket
throws. Chunk it yourself — silently splitting or cutting here would hide a
data-loss bug behind a convenience.

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

CI runs macOS and Linux x86-64. Also verified locally on macOS 26 / Swift 6.4
and Linux aarch64 / Swift 6.2.4 — 10 tests, both.

## Provenance

Extracted from [Eldr](https://github.com/SnoobieJunes/Eldr), a post-quantum,
decentralised, E2EE messenger, where it implements PQRC SPEC §7. Eldr remains
the upstream source of truth; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Related

Other single-purpose primitives extracted from the same codebase:

- [untrusted-data-envelope](https://github.com/SnoobieJunes/untrusted-data-envelope)
  — structural prompt-injection containment
- [swift-credential-redactor](https://github.com/SnoobieJunes/swift-credential-redactor)
  — secret-shape scrubbing for agent output

## License

[Apache-2.0](LICENSE).
