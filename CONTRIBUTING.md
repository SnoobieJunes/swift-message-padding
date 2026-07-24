# Contributing to swift-message-padding

Thanks for wanting to help.

This library is **extracted from [Eldr](https://github.com/SnoobieJunes/Eldr)**,
which remains the upstream source of truth. Changes flow Eldr → here. If your
change also applies upstream, say so in the PR and it will be mirrored — you do
not need to open two PRs.

## Ground rules

- **One primitive per repo.** This library deliberately does one thing. Feature
  requests that broaden its scope will usually be declined in favour of a new,
  separate library — that is the design, not a brush-off.
- **Dependencies are close to sacred.** A PR that adds a dependency needs an
  argument for why the alternative is worse.
- **Tests are the deliverable.** Behaviour changes need a test that fails
  before and passes after. Security-relevant behaviour needs an adversarial
  test, not just a happy-path one.

## Building and testing

```bash
swift build
swift test
```

That is the whole loop — no simulator, no network, no system clock.

## Style

- Swift 6 language mode, strict concurrency. No `@unchecked Sendable` without
  a written justification comment.
- Typed errors. No `try!`, no force unwraps, no `fatalError` outside
  genuinely unreachable code.
- Match the surrounding comment density. This codebase explains *why*, at
  length, in security-relevant places. That is deliberate.

## Licensing and sign-off

Contributions are accepted under the **Apache License 2.0** (inbound = outbound).
Sign off your commits with `git commit -s` (the
[DCO](https://developercertificate.org/)) to certify you have the right to
submit the work.

## Security

Never open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).
