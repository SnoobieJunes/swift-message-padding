# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — unreleased

Tagged at publication; the README install snippets pin `from: "0.1.0"`.

### Added

- Fixed-size bucket padding, applied to plaintext before AEAD encryption, so
  ciphertext length leaks a bucket instead of an exact message length:
  `Padding.pad`, `Padding.unpad`, `Padding.bucket(for:)`, and a
  caller-supplied bucket ladder
- Wire format `u32be(length) || plaintext || zero fill`, with the length prefix
  outside the bucket accounting
- `unpad` rejects buffers whose declared length does not match the bucket
  present, so a truncated buffer fails rather than decoding to a shorter
  plaintext
