// SPDX-License-Identifier: Apache-2.0
import Foundation

/// Fixed-size bucket padding: defeats size-based traffic analysis.
/// Applied to plaintext BEFORE AEAD encryption.
///
/// **The problem.** Encryption hides *what* you said. It does not hide *how
/// much* you said. An observer who can see ciphertext lengths — a relay, a
/// network operator, anyone on the path — reads a surprising amount from that
/// alone: which of two canned replies you sent, whether a message is "ok" or a
/// paragraph, when a conversation changes character. Length is metadata that
/// survives end-to-end encryption.
///
/// **The fix.** Round every plaintext up to one of a small set of buckets
/// before sealing it. All 200-byte messages and all 12-byte messages look
/// identical on the wire. The cost is bandwidth; the benefit is that ciphertext
/// length carries `log2(buckets.count)` bits instead of `log2(maxSize)`.
///
/// **Layout:** `u32be(plaintext length) || plaintext || zero fill`, where the
/// zero fill extends to the bucket boundary. The 4-byte length prefix sits
/// *outside* the bucket accounting, so a plaintext of exactly `inlineSizeLimit`
/// bytes still fits the largest bucket. Total padded size for bucket `B` is
/// therefore `B + 4`. What reaches the wire depends on your AEAD framing —
/// AES-GCM adds a 16-byte tag, and CryptoKit's combined representation also
/// carries a 12-byte nonce — but that overhead is constant across buckets,
/// which is the only part that matters here.
///
/// ```swift
/// let padded = try Padding.pad(Data("hello".utf8))   // 260 bytes (256 + 4)
/// let sealed = try AES.GCM.seal(padded, using: key)  // your crypto, not ours
/// // …
/// let plaintext = try Padding.unpad(opened)          // back to "hello"
/// ```
///
/// Extracted from [Eldr](https://github.com/SnoobieJunes/Eldr), where it
/// implements PQRC SPEC §7.
public enum Padding {

    // MARK: - Configuration

    /// The bucket ladder, in bytes, ascending.
    ///
    /// Powers of four rather than powers of two: fewer buckets means less
    /// information in a length observation, and the wasted bytes are cheap for
    /// text. A messenger carrying different traffic may want a different
    /// ladder — see ``bucket(for:buckets:)`` and the other
    /// `buckets:`-taking overloads, which take one explicitly.
    public static let defaultBuckets = [256, 1024, 4096, 16384, 65536]

    /// Plaintext larger than this is never padded inline — the caller must
    /// chunk it. Equal to the largest default bucket.
    public static let inlineSizeLimit = 65536

    // MARK: - Errors

    public enum PaddingError: Error, Equatable, Sendable {
        /// Plaintext is larger than the largest bucket. Chunk it instead:
        /// silently splitting or truncating here would hide a data-loss bug.
        case plaintextExceedsLargestBucket(size: Int, largestBucket: Int)
        /// The padded buffer is not a well-formed padding of any bucket: too
        /// short, or its declared length does not match the bucket present.
        /// Note that fill bytes are NOT inspected — a buffer with the right
        /// shape but corrupted padding passes. Integrity is your AEAD's job.
        case malformedPadding
        /// A caller-supplied bucket ladder was empty or not strictly ascending.
        case invalidBuckets
        /// A negative length was passed to ``Padding/bucket(for:buckets:)``.
        case negativeLength
    }

    // MARK: - API

    /// Smallest bucket that holds `length` plaintext bytes.
    public static func bucket(for length: Int, buckets: [Int] = defaultBuckets) throws -> Int {
        try validate(buckets)
        guard length >= 0 else { throw PaddingError.negativeLength }
        guard let bucket = buckets.first(where: { $0 >= length }) else {
            throw PaddingError.plaintextExceedsLargestBucket(
                size: length, largestBucket: buckets[buckets.count - 1])
        }
        return bucket
    }

    /// Pad `plaintext` up to its bucket. Feed the result to your AEAD.
    public static func pad(_ plaintext: Data, buckets: [Int] = defaultBuckets) throws -> Data {
        let bucket = try bucket(for: plaintext.count, buckets: buckets)
        var padded = Data(bigEndian: UInt32(plaintext.count))
        padded.append(plaintext)
        padded.append(Data(count: bucket - plaintext.count))
        return padded
    }

    /// Recover the plaintext from a padded buffer produced by ``pad(_:buckets:)``.
    ///
    /// Rejects anything whose declared length does not map to the bucket
    /// actually present. That check is the point: without it, a truncated or
    /// tampered buffer decodes to a *shorter, attacker-chosen* plaintext rather
    /// than failing. Run it after AEAD authentication, not instead of it.
    public static func unpad(_ padded: Data, buckets: [Int] = defaultBuckets) throws -> Data {
        // `Int(exactly:)`, not `Int(_:)`: `length` comes straight from
        // attacker-controllable bytes, and on a 32-bit platform the plain
        // conversion TRAPS for any declared length above Int32.max — a crash
        // where the contract promises a thrown error.
        guard padded.count >= 4, let raw = padded.uint32BE(at: 0),
            let length = Int(exactly: raw)
        else { throw PaddingError.malformedPadding }
        guard padded.count >= 4 + length else { throw PaddingError.malformedPadding }
        guard let expectedBucket = try? bucket(for: length, buckets: buckets),
            padded.count == 4 + expectedBucket
        else {
            throw PaddingError.malformedPadding
        }
        // Slice-relative, NOT absolute: `uint32BE(at:)` offsets from
        // `startIndex`, and `Data` slices do not rebase their indices. A literal
        // `4..<…` here would read below `startIndex` (and trap) for any caller
        // that passes a non-zero-based slice.
        let lo = padded.startIndex + 4
        return padded.subdata(in: lo..<(lo + length))
    }

    // MARK: - Internals

    private static func validate(_ buckets: [Int]) throws {
        guard let first = buckets.first, first > 0 else { throw PaddingError.invalidBuckets }
        guard zip(buckets, buckets.dropFirst()).allSatisfy({ $0 < $1 }) else {
            throw PaddingError.invalidBuckets
        }
    }
}

// MARK: - Byte helpers

extension Data {
    /// Big-endian 4-byte encoding of a UInt32.
    fileprivate init(bigEndian value: UInt32) {
        self.init([
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
        ])
    }

    /// Reads a big-endian UInt32 at `offset` (relative to `startIndex`); nil if
    /// out of bounds.
    fileprivate func uint32BE(at offset: Int) -> UInt32? {
        guard offset >= 0, count >= offset + 4 else { return nil }
        let i = startIndex + offset
        return (UInt32(self[i]) << 24) | (UInt32(self[i + 1]) << 16)
            | (UInt32(self[i + 2]) << 8) | UInt32(self[i + 3])
    }
}
