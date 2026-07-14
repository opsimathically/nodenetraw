# Monorepo migration report

Date: 2026-07-13

## Outcome

The renamed `nodenet` repository now separates repository orchestration, public
Node packages, and internal Rust crates without changing the
`@opsimathically/nodenetraw` API or release version.

```text
nodenet/
  package.json                 private npm workspace/orchestration
  package-lock.json            shared npm lock
  Cargo.toml                   virtual Rust workspace and release profile
  Cargo.lock                   shared Rust lock
  packages/
    nodenetraw/                implemented public package
      src/ test/ scripts/ npm/
    nodenetscanner/            private documentation placeholder only
  crates/
    nodenetraw-native/         existing N-API crate
      fuzz/                    independent cargo-fuzz workspace and lock
  ai_documentation/            cross-workspace plans and decisions
```

## Preserved contracts

- The public package remains `@opsimathically/nodenetraw@0.1.0-rc.6`, Linux
  only, Node 26+, ESM-only, and zero-runtime-dependency.
- The existing Rust crate, N-API binary name, Node-API 10 target, glibc 2.28
  artifact ceiling, and x86-64/AArch64 target-package model are unchanged.
- Root commands continue to build, test, harden, stress, and assemble the raw
  package. Privileged commands continue to build as the invoking repository
  owner before entering a disposable network namespace.
- Direct publication from source remains refused. Staged target packages remain
  the only publication inputs.

## New boundaries

- npm workspaces provide development linking; contributors must not use manual
  `npm link` for internal packages.
- The root npm package is private and has development tooling only. Production
  package metadata remains under the owning package. An explicit lifecycle guard
  also rejects root publication because npm dry-run does not treat the private
  flag as an operator-visible refusal.
- Cargo shares a root lock and release profile. The fuzz crate remains an
  independent nested workspace because that is required by `cargo-fuzz`.
- `nodenetscanner` has no exports, source, native crate, runtime dependency, or
  release path. Its placeholder prevents accidental claims that scanner
  functionality already exists.
- Future native sharing must occur through reviewed, non-published Cargo crates
  at compile time. Packet hot paths must not bounce through JavaScript between
  addons.

## Path-sensitive changes

- napi-rs builds resolve `crates/nodenetraw-native/Cargo.toml` from the raw
  package workspace.
- release scripts derive both package and repository roots from their own file
  location; staged output lives under `packages/nodenetraw/release`.
- artifact provenance hashes the root Cargo lock.
- CI fuzz, sanitizer, advisory, and uploaded-artifact paths follow the new
  crate/package locations.
- ESLint and Prettier remain root-managed and ignore generated output at any
  workspace depth.
- package documentation links back to root planning and contributor context.
- obsolete ignored output from the former root `build`, `dist`, `release`, and
  `native/target` locations was removed after clean workspace verification.

## Verification

All commands ran from the repository root on x86-64 glibc Linux with Node 26.4.0
and the pinned Rust 1.97.0 toolchain unless stated otherwise.

- `npm ci`: clean workspace install completed; 155 packages audited with zero
  vulnerabilities. npm linked both workspace packages.
- `npm run ci`: formatting, ESLint, strict TypeScript, Rust formatting, Clippy,
  38 Rust tests, native/TypeScript builds, declaration fixtures, 89 Node tests
  (74 passed and 15 privileged cases skipped), production audit, and release
  policy/license review all passed.
- `npm run release:consumer-test`: built the optimized x64 GNU addon, assembled
  the two staged packages, packed and installed them into a clean temporary
  consumer with scripts disabled, and passed both ESM and synchronous
  `require()` checks.
- `npm run release:verify-artifact`: verified an x86-64 stripped ELF with a
  highest required glibc symbol of 2.16.0, below the declared 2.28 ceiling.
- `npm run release:reproducibility`: two clean optimized builds produced the
  identical SHA-256
  `6f96f223b76d2f6727aca90995e6cf5dadec5e2ffb7ed6dd59718296416e8da6`.
- `npm publish --dry-run --tag next --access public` passed for both the staged
  x64 target package and staged root package. Expected-failure checks proved
  that publication from either the private workspace root or the raw-package
  source tree is refused before packing/publishing.
- A disposable privileged Node 26 Debian container ran the complete network
  namespace suite: all 15 IPv4, IPv6, packet, event, ICMP, traceroute, queue,
  cancellation, and Worker tests passed. The host network namespace was not
  modified.
- Shell syntax checks passed for every package test harness, and the repository
  and package MIT license copies are identical.

Native AArch64 execution was not run and remains an explicit untested
publication gate.
