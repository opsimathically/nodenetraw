# Phase 16 completion report

Date: 2026-07-13

## Outcome

Phase 16 is complete. `crates/nodenet-protocols` is a non-published,
syscall-free Rust library with no N-API dependency and project code compiled
under `unsafe_code = "deny"` and warnings-as-errors. It establishes the bounded
codec boundary without implementing the Phase 17 link/network protocol surface
or any scanner policy.

The crate now provides:

- exact-width MAC, IPv4, IPv6, EtherType, IP-protocol, wire-port, checked probe-
  port, checksum, and packet-span types;
- stable project-owned parse/build errors and resource/layer/field identifiers;
- the declared IP, Ethernet, VLAN, IPv6-extension, TCP-option, owned-payload,
  and owned-option ceilings;
- strict structural inspection and explicitly named compatible ICMP-quote
  inspection with no silent strict-to-lax fallback;
- prevalidated packet plans that report exact required length, leave short
  caller buffers untouched, allocate nothing on caller-owned writes, and use
  exactly one checked allocation on owned construction;
- deterministic independent wire bytes shared from
  `test/fixtures/protocol/ethernet-ipv4-udp.hex`;
- mutation/arbitrary-byte tests, allocation assertions, parser/serializer fuzz
  targets, and a release-mode microbenchmark.

## Dependency review

The implementation-start review selected `etherparse` 0.20.3 exactly and
disabled all default features. Its declared MSRV is Rust 1.83.0, below this
workspace's pinned Rust 1.97.0. Its license is `MIT OR Apache-2.0`; the locked
normal transitive graph is only `arrayvec` 0.7.8, also dual licensed. Neither
package has a build script in the selected graph. `cargo audit` reports no known
advisories in the root or protocol-fuzz lock.

`stats_alloc` 0.1.10 is an exact-pinned, MIT-licensed development-only
dependency used to verify allocation contracts and emit the benchmark count. It
is absent from runtime consumers. `libfuzzer-sys` remains isolated in the
separately locked fuzz workspace.

`etherparse` explicitly describes its API as changing and its ICMP/ICMPv6 and
IPv6-extension support as incomplete. No dependency type appears in the public
crate surface. No dependency defragmenter is enabled or called.

## Coverage and ownership matrix

| Surface                    | Dependency capability used or available                         | Stable owner and owning phase                                                                                      |
| -------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Bounded slice dispatch     | Strict and lax allocation-free slicing                          | Project wrapper in Phase 16; compatible mode is IP/ICMP-quote-only                                                 |
| Ethernet II                | Header parse/write available                                    | Full bounded codec and public internal types: project, Phase 17                                                    |
| 802.1Q/802.1ad VLAN        | Single/double VLAN support available                            | Two-header ceiling and accepted tag semantics: project, Phase 17                                                   |
| ARP                        | Generic ARP support available                                   | Ethernet/IPv4 validation, unknown combinations, builders: project, Phase 17                                        |
| IPv4                       | Header/options support available                                | Fragment semantics, exact limits, stable results/templates: project, Phase 17                                      |
| IPv6                       | Base header and common extensions available, not all extensions | Complete accepted extension walk, order/byte/count bounds, no jumbograms: project, Phase 17                        |
| Fragmentation              | Headers can be represented; example reassembly exists           | Reassembly remains disabled; explicit fragment metadata only: project, Phase 17                                    |
| UDP                        | Header/checksum support available                               | Stable codec, checksum policy, templates: project, Phase 18                                                        |
| TCP                        | Header/options/checksum support available                       | Scanner flag/options validation and templates: project, Phase 18                                                   |
| ICMPv4                     | Dependency supports a subset of message types                   | Accepted scanner/control breadth and gaps: project-owned codecs, Phase 18; existing TypeScript remains independent |
| ICMPv6                     | Dependency supports a subset of message types                   | Errors, Echo, pseudo-header checksums, NDP messages/options: project-owned where missing, Phase 18                 |
| Correlation                | Not delegated to the codec dependency                           | Canonical HMAC representation/comparison frozen by D-032; implementation: project, Phase 18                        |
| Packet I/O, netlink, N-API | None                                                            | Explicitly outside this crate; later owning phases                                                                 |

Dependency gaps do not reduce the accepted Phase 17 or 18 surface. Each owning
phase must either implement the gap in bounded project code or record and obtain
approval for an explicit scope decision before it can exit.

## Safety and parser semantics

The parser checks the enclosing slice ceiling before dependency dispatch. The
strict path calls only strict parsing. `CompatibleIcmpQuote` is rejected for an
Ethernet-starting slice; for IP input it accepts only length truncation or a
declared-length fallback and returns `IncompleteQuote`. Content errors remain
structured malformed errors. Parsing is borrowed and allocation-free.

Owned payload and option copies have independent preallocation ceilings.
`PacketPlan` validates complete encoded length before output mutation. A short
buffer returns its required and actual lengths without changing any byte. The
owned control/test path allocates an exactly sized vector only after validation.

This phase does not yet claim semantic enforcement of every VLAN, IPv6
extension, fragment, TCP-option, or jumbogram rule; those are required parts of
the Phase 17/18 codecs. The constants and error vocabulary are frozen now so
those parsers cannot introduce unbounded policy later.

## Correlation decision

D-032 freezes the Phase 18 correlation representation: domain-separated fixed-
width canonical input, HMAC-SHA-256, an independent 32-byte OS-random session
key, 128-bit UDP/ICMP payload tokens, the protocol-limited 32-bit TCP sequence
token, and reviewed constant-time comparison for payload tokens. No
cryptographic crate or entropy syscall was added in Phase 16.

## Verification

The following gates passed on the x86-64 development host:

```sh
cargo fmt --all --check
cargo clippy -p nodenet-protocols --all-targets --all-features -- -D warnings
cargo test -p nodenet-protocols --locked
cargo check --manifest-path crates/nodenet-protocols/fuzz/Cargo.toml --locked
cargo +nightly fuzz run parse --fuzz-dir crates/nodenet-protocols/fuzz -- -runs=10000 -max_len=70000 -rss_limit_mb=1024
cargo +nightly fuzz run serialize --fuzz-dir crates/nodenet-protocols/fuzz -- -runs=1000 -max_len=70000 -rss_limit_mb=1024
cargo bench -p nodenet-protocols --bench foundation --locked
cargo check -p nodenet-protocols --target x86_64-unknown-linux-gnu --locked
cargo check -p nodenet-protocols --target aarch64-unknown-linux-gnu --locked
cargo audit --file Cargo.lock
cargo audit --file crates/nodenet-protocols/fuzz/Cargo.lock
```

The local release baseline was approximately 23 ns per strict Ethernet/IPv4/UDP
structural inspection and 1 ns per caller-owned fixture copy, with zero
allocations in each measured path. These values are host-local regression
anchors, not throughput claims.

Both target checks pass. Native AArch64 execution remains CI-owned because the
local host is x86-64.

## Scope confirmation and next action

No TypeScript or Node API changed. No descriptor, syscall, N-API, route-context,
scheduler, live-scanner, DNS, reassembly, or extreme-backend code was added.
Phase 17 is next: implement the bounded Ethernet/VLAN/ARP/IPv4/IPv6 envelope and
reusable frame templates against this foundation and coverage matrix.
