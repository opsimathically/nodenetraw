# Phase 18 completion report

Date: 2026-07-13

## Outcome

Phase 18 is complete. The internal, non-published `nodenet-protocols` crate now
owns the scanner-relevant transport/control codecs and pure response-
correlation layer required before a scheduler or live scanner is introduced. The
implementation remains free of N-API, descriptors, syscalls, host-state
mutation, scanner result policy, and project-owned unsafe code. No public Node
API, package version, or release artifact changed.

The implemented surface is:

- TCP construction and checksum-validated parsing for all nine standardized
  flags, ports, sequence/acknowledgment, window, urgent pointer, payload, and
  bounded MSS, window-scale, SACK-permitted, SACK, timestamp, NOP, and safely
  preserved unknown options;
- UDP construction and parsing with correct IPv4/IPv6 pseudo-header checksums,
  explicit IPv4 checksum omission, mandatory IPv6 checksums, transmitted-zero
  checksum normalization, trailing-capture separation, and bounded owned payload
  copies;
- ICMPv4 Echo, Destination Unreachable, Time Exceeded, and Parameter Problem,
  including checksum validation and safely decoded IPv4 TCP/UDP/Echo quotes;
- RFC 4443 ICMPv6 Echo, Destination Unreachable, Packet Too Big, Time Exceeded,
  and Parameter Problem with IPv6 pseudo-header checksums and nested quote
  results that do not invalidate a structurally valid outer error;
- RFC 4861 Router Solicitation/Advertisement, Neighbor Solicitation/
  Advertisement, and Redirect construction/parsing, fixed-capacity known and
  unknown options, and message-specific source, destination, target, flag,
  option-placement, code, minimum-length, and hop-limit-255 validation; and
- pure ARP/NDP/TCP/UDP/ICMP evidence classification with protocol-specific
  strength rather than final scan-state policy.

## Correlation and safety boundary

D-032's canonical 70-byte correlation input is implemented exactly. It is
domain-separated by `nodenet/probe/v1` and binds family, protocol, attempt,
fixed-width source/destination addresses, ports, ICMP identifier/sequence, and
internal probe ID. HMAC-SHA-256 produces a 32-byte value. UDP and ICMP use its
first 16 bytes; TCP uses its first four bytes as the sequence and requires the
reply acknowledgment to equal that value plus one modulo 2^32.

`SessionSecret` accepts exactly 32 bytes supplied by the future native scanner
runtime's OS random source. The protocol crate deliberately performs no entropy
syscall. Secret debug output is redacted and key storage is zeroized on drop.
Payload-token comparisons use a reviewed constant-time primitive after tuple
validation. The exact HMAC output is checked against an independently computed
SHA-256 vector.

Evidence is deliberately not overstated. Exact ICMP payload tokens are labeled
128-bit strong evidence. Exact TCP sequence/acknowledgment evidence is labeled
32-bit strong evidence. Direct UDP, ARP, and Neighbor Advertisement responses
remain tuple-correlated and unauthenticated. Valid ICMP quotes ending before a
UDP/ICMP token are explicitly truncated/weak; a present wrong token is rejected.
Non-first fragments, unusably short quotes, wrong protocols, tuples, flags,
identifiers, sequences, and acknowledgments are rejected.

A bounded reuse guard prevents a TCP/UDP source port or ICMP identifier from
being reserved while it is outstanding or retained for late-response grace. It
accepts caller-supplied monotonic time, has no clock syscall, rejects deadline
overflow, and is capped at 262,144 entries.

All input-directed collections remain fixed-capacity or separately bounded. TCP
options are capped at 40 entries/40 encoded bytes. NDP is capped at 64 options
and 4,096 option bytes. Packet and transport lengths retain their wire- format
ceilings. Builders complete validation and output-capacity checks before
mutation; parsers validate declared lengths and checksums before typed access.

## Independent evidence and hostile coverage

The Phase 18 integration suite includes:

- the frozen HMAC input/output vector independently produced with Node's crypto
  implementation;
- an independent `etherparse` IPv6 UDP checksum comparison;
- byte parity with the existing TypeScript ICMPv4 Echo wire representation;
- TCP option round trips including unknown preservation and checksum corruption;
- IPv4 checksum omission versus IPv6 checksum requirements;
- typed ICMPv4/ICMPv6 Echo and nested error quotes;
- all five NDP message families, unknown options, invalid hop limit, zero option
  units, invalid placement, DAD source-link option prohibition, and solicited
  multicast Neighbor Advertisement rejection;
- valid, forged, truncated, fragmented, direct, strong, weak, late-grace, and
  conflicting correlation cases; and
- a checked-in classic-pcap fixture replayed into identical normalized UDP
  evidence.

The parser fuzz surface now invokes every TCP, UDP, ICMPv4, ICMPv6, NDP, and
nested quoted-packet entry point for both relevant address families alongside
the Phase 16/17 parsers. A smoke run completed 31,538 expanded parser-corpus
executions and 1,570,202 serializer executions without a crash or artifact.

## Dependencies

Phase 18 exact-pins feature-minimal RustCrypto crates behind project-owned
types: `hmac` 0.13.0 with zeroization, `sha2` 0.11.0, `subtle` 2.6.1, and
`zeroize` 1.9.0. Default features are disabled. Their transitive graph is
locked; root and separate protocol-fuzz lockfile RustSec scans report no known
vulnerabilities. The release dependency/license policy gate passes.

## Verification

The following gates passed on the x86-64 development host:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo check -p nodenet-protocols --target x86_64-unknown-linux-gnu --locked
cargo check -p nodenet-protocols --target aarch64-unknown-linux-gnu --locked
cargo audit --file Cargo.lock
cargo audit --file crates/nodenet-protocols/fuzz/Cargo.lock
cargo +nightly fuzz run parse --fuzz-dir crates/nodenet-protocols/fuzz -- -max_total_time=15 -max_len=70000
cargo +nightly fuzz run serialize --fuzz-dir crates/nodenet-protocols/fuzz -- -max_total_time=15 -max_len=70000
npm run format:check
npm run lint
npm run typecheck
npm test
npm run hardening:verify
```

The protocol crate now has 34 ordinary tests and the native crate has 38. The
Node suite passed 74 ordinary tests with 16 privileged opt-in tests skipped.
AArch64 cross-compilation passes; native AArch64 execution remains explicitly
untested and CI-owned.

## Scope confirmation and next action

No network-context syscall, namespace transition, route or neighbor snapshot,
descriptor, live transmit/receive loop, scheduler, timer wheel, scanner result
state, N-API export, or JavaScript packet crossing was added. The Phase 18 exit
gate is satisfied by project-owned builders/parsers/classifiers for ARP, NDP
Neighbor Solicitation/Advertisement, ICMPv4/v6 Echo, TCP SYN/replies, and UDP
direct/quoted responses at their documented evidence strengths.

Phase 19 is next: the bounded, immutable `NETLINK_ROUTE` snapshot foundation.
