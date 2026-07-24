// SPDX-License-Identifier: Apache-2.0
import Foundation
import Testing

@testable import MessagePadding

@Suite("Bucket padding")
struct MessagePaddingTests {

    @Test("every plaintext lands on a bucket boundary + 4")
    func padsToBucketBoundary() throws {
        for size in [0, 1, 255, 256, 257, 1023, 1024, 4095, 16384, 65535, 65536] {
            let padded = try Padding.pad(Data(count: size))
            let bucket = try Padding.bucket(for: size)
            #expect(padded.count == bucket + 4, "size \(size) → \(padded.count), want \(bucket + 4)")
            #expect(Padding.defaultBuckets.contains(bucket))
        }
    }

    @Test("round trips exactly")
    func roundTrips() throws {
        for size in [0, 1, 100, 256, 257, 5000, 65536] {
            let plaintext = Data((0..<size).map { UInt8($0 % 251) })
            let recovered = try Padding.unpad(try Padding.pad(plaintext))
            #expect(recovered == plaintext, "size \(size) did not round trip")
        }
    }

    @Test("indistinguishable lengths within a bucket")
    func lengthsCollapse() throws {
        // The entire point of the library: two very different messages must
        // produce byte-identical padded lengths.
        let short = try Padding.pad(Data("ok".utf8))
        let long = try Padding.pad(Data(String(repeating: "x", count: 250).utf8))
        #expect(short.count == long.count)
    }

    @Test("oversize plaintext is refused, never truncated")
    func refusesOversize() {
        #expect(throws: Padding.PaddingError.self) {
            _ = try Padding.pad(Data(count: Padding.inlineSizeLimit + 1))
        }
    }

    @Test("declared length must match the bucket actually present")
    func rejectsLengthBucketMismatch() throws {
        // A 10-byte plaintext lives in the 256 bucket. Claim it is 300 bytes:
        // 300 would map to the 1024 bucket, but the buffer is 260 bytes.
        var tampered = try Padding.pad(Data(count: 10))
        tampered[0] = 0
        tampered[1] = 0
        tampered[2] = 1
        tampered[3] = 44  // 300
        #expect(throws: Padding.PaddingError.malformedPadding) {
            _ = try Padding.unpad(tampered)
        }
    }

    @Test("truncated buffers are refused")
    func rejectsTruncated() throws {
        let padded = try Padding.pad(Data("hello".utf8))
        for cut in [1, 2, 4, 100] {
            #expect(throws: Padding.PaddingError.malformedPadding) {
                _ = try Padding.unpad(padded.dropLast(cut))
            }
        }
        #expect(throws: Padding.PaddingError.malformedPadding) {
            _ = try Padding.unpad(Data([0x00, 0x01]))
        }
    }

    @Test("unpad works on a non-zero-based slice")
    func handlesRebasedSlice() throws {
        // `Data` slices do not rebase their indices; an implementation that
        // used absolute offsets would read below startIndex and trap here.
        let padded = try Padding.pad(Data("slice me".utf8))
        let prefixed = Data([0xAA, 0xBB]) + padded
        let slice = prefixed.dropFirst(2)
        #expect(slice.startIndex == 2)
        #expect(try Padding.unpad(slice) == Data("slice me".utf8))
    }

    @Test("custom bucket ladders are honoured")
    func customBuckets() throws {
        let buckets = [16, 64, 512]
        let padded = try Padding.pad(Data(count: 20), buckets: buckets)
        #expect(padded.count == 64 + 4)
        #expect(try Padding.unpad(padded, buckets: buckets).count == 20)
        #expect(throws: Padding.PaddingError.self) {
            _ = try Padding.pad(Data(count: 513), buckets: buckets)
        }
    }

    @Test("invalid bucket ladders are rejected")
    func rejectsBadBuckets() {
        for bad in [[], [0, 16], [64, 16], [16, 16]] {
            #expect(throws: Padding.PaddingError.invalidBuckets) {
                _ = try Padding.bucket(for: 1, buckets: bad)
            }
        }
    }

    @Test("padding is deterministic and zero-filled")
    func deterministicZeroFill() throws {
        let a = try Padding.pad(Data("abc".utf8))
        let b = try Padding.pad(Data("abc".utf8))
        #expect(a == b)
        #expect(a.dropFirst(4 + 3).allSatisfy { $0 == 0 })
    }
}
