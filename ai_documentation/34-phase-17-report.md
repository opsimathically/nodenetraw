# Phase 17 completion report

Date: 2026-07-13

## Outcome

Phase 17 is complete. The internal, non-published `nodenet-protocols` crate now
constructs and parses the complete bounded L2/L3 envelope required by the first
portable scanner. The crate remains free of N-API, descriptors, syscalls,
scanner policy, and project-owned unsafe code. No public Node package API or
release version changed.

The implemented surface is:

- Ethernet II construction/parsing with zero, one, or two checked 802.1Q/
  802.1ad tags;
- canonical Ethernet/IPv4 ARP request and reply construction plus length-first
  parsing that preserves other hardware/protocol/address-length/operation
  combinations as structured borrowed unknown values;
- IPv4 DSCP, ECN, identification, flags, fragment offset, TTL, protocol,
  options, total length, checksum, payload, and trailing-capture handling;
- IPv6 traffic class, flow label, payload length, hop limit, addresses, and
  bounded Hop-by-Hop, Routing, Fragment, Destination Options, and Authentication
  extension construction/traversal;
- explicit unfragmented, first-fragment, and non-first-fragment state without
  reassembly;
- explicit reachable, insufficient-header, non-first-fragment, ESP,
  No-Next-Header, and unknown upper-layer terminal states;
- separate safe noncanonical-order/duplicate observations rather than treating
  them as truncation or scanning beyond an opaque terminal;
- reusable immutable frame templates with checked, non-overlapping descriptors
  for MAC/IP addresses, IP lengths/identifiers/checksums, IPv6 fragment IDs, and
  bounded tokens; and
- caller-owned transactional writers plus owned construction for control and
  test paths.

## Bounds and safety behavior

Every parser rejects its enclosing byte ceiling before traversal. Ethernet is
limited to 65,597 bytes and two VLAN headers. IPv4 is limited by its 16-bit
total length. IPv6 jumbograms are unsupported; non-jumbogram packets are at most
65,575 bytes, with at most eight extension headers and 2,048 combined extension
bytes. IPv4 options are at most 40 bytes. Template descriptors are capped at 32
and tokens at 32 bytes.

All structural arithmetic is checked before slicing or allocation. Strict mode
requires the declared IP payload. `CompatibleIcmpQuote` permits only a missing
payload suffix after a complete valid base header and every present extension;
it never accepts a truncated extension, malformed option, bad IPv4 checksum, or
invalid fragment length. Non-first IPv6 fragments stop immediately after their
Fragment header. ESP, unknown Next Header values, and No Next Header are opaque
terminals and are never searched for a plausible transport header.

IPv4 validates option TLVs, checksum, IHL/total length, incompatible DF/
fragment fields, and the eight-byte size rule for non-final fragments. IPv6
validates extension size encodings, option TLVs, Fragment reserved bits, the
non-final fragment size rule, AH bounds, traversal count/bytes, and canonical
construction order. Safe received duplicates and noncanonical orders remain
parseable with explicit conformance flags. The final review corrected one subtle
order case: a final Destination Options header is canonical without a Routing
header, while Destination Options placed before Fragment/AH without an
intervening Routing header is not.

Builders finish all validation and capacity checks before touching caller
storage. Tests prove unchanged short output for ARP, Ethernet, IPv4, IPv6, and
templates. Parsing and caller-owned construction allocate zero times in the
instrumented allocation tests. Maximum legal IPv4, IPv6, double-tagged Ethernet,
IPv6 extension-count/byte, and AH-length cases are covered alongside the first
illegal value.

## Independent and live wire evidence

Three independently specified fixtures live in `test/fixtures/protocol`:

- Ethernet/ARP request;
- Ethernet/IPv4/UDP with a known IPv4 checksum; and
- Ethernet/IPv6 with Hop-by-Hop and first-Fragment headers.

Project builders reproduce all three byte-for-byte. The IPv4 and IPv6 frames
also parse successfully through exact-pinned `etherparse` as a differential
oracle; dependency representations remain private.

The `phase17_vectors` example generates those frames through the project
builders. `npm run test:phase17:namespace` injects the generated frames through
`@opsimathically/nodenetraw` raw `AF_PACKET` I/O across the disposable veth
fixture and asserts that the receiving interface captures every ARP, IPv4, and
IPv6 byte exactly. This opt-in gate passed locally using an unprivileged user/
network namespace and is included in scheduled hardening CI. The existing sudo-
safe wrapper also supports `sudo npm run test:phase17:namespace` where user
namespaces are disabled.

## Fuzzing, dependencies, and baseline

The existing separately locked parser and serializer fuzz targets now exercise
every Phase 17 parser, both parse modes, bounded IPv4/IPv6/ARP/Ethernet
construction, and parse-after-build invariants. A 20,000-run smoke pass for each
target completed without a crash. Deterministic arbitrary-byte and mutation
tests remain part of ordinary Rust tests.

Phase 17 adds no dependency. The runtime graph remains `etherparse` 0.20.3 with
default features disabled and its `arrayvec` 0.7.8 transitive dependency. Root
and protocol-fuzz lockfile advisory scans report no known vulnerabilities; the
existing license/release-policy gate passes.

The local release-mode regression baseline was approximately 103 ns for one
Ethernet/IPv4 plus one Ethernet/IPv6 extension-chain parse pair, 13 ns for one
caller-owned IPv4 build, and 8 ns for one checked template copy/patch. All three
measured paths allocate zero times. These are host-local regression anchors, not
throughput claims.

## Verification

The following gates passed on the x86-64 development host:

```sh
cargo fmt --all --check
cargo clippy -p nodenet-protocols --all-targets --all-features --locked -- -D warnings
cargo test -p nodenet-protocols --locked
cargo check -p nodenet-protocols --target x86_64-unknown-linux-gnu --locked
cargo check -p nodenet-protocols --target aarch64-unknown-linux-gnu --locked
cargo +nightly fuzz run parse --fuzz-dir crates/nodenet-protocols/fuzz -- -runs=20000 -max_len=70000 -rss_limit_mb=2048
cargo +nightly fuzz run serialize --fuzz-dir crates/nodenet-protocols/fuzz -- -runs=20000 -max_len=70000 -rss_limit_mb=2048
npm run benchmark:protocols
npm run test:phase17:namespace
cargo audit --file Cargo.lock
cargo audit --file crates/nodenet-protocols/fuzz/Cargo.lock
npm run hardening:verify
npm run ci
```

The protocol crate has 24 ordinary tests: three unit tests, one exact-allocation
test, seven foundation tests, and thirteen Phase 17 integration tests. Both
cross-target checks pass. Native AArch64 execution remains CI-owned because the
local development host is x86-64.

## Scope confirmation and next action

No transport/control codec, correlation secret, entropy source, N-API export,
descriptor, route-context syscall, scheduler, or live scanner was added. Phase
18 is next: TCP, UDP, ICMPv4, ICMPv6, Neighbor Discovery, pseudo-header
checksums, quoted evidence, and the already frozen session-keyed correlation
contract.
