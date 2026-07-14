# nodenet

`nodenet` is the development workspace for Linux-native Node.js networking
libraries implemented with TypeScript, Rust, and Node-API.

## Packages

- [`@opsimathically/nodenetraw`](packages/nodenetraw/README.md) is the active,
  Linux-only raw socket and ICMP/traceroute package.
- [`@opsimathically/nodenetscanner`](packages/nodenetscanner/README.md) is a
  private planning placeholder for a future scanner package. It has no API or
  implementation yet.

The public packages remain independently versioned. Performance-sensitive Rust
code can be shared as compile-time workspace crates, while each Node package
keeps an explicit public API and native-addon boundary.

## Development

The repository requires Node.js 26+, npm 11+, and the Rust toolchain pinned in
[`rust-toolchain.toml`](rust-toolchain.toml).

```sh
npm ci
npm run ci
```

Root commands orchestrate the relevant workspace package. Package-specific
source, tests, release tooling, and documentation live under `packages/`; Rust
crates live under `crates/`.

Licensed under the [MIT License](LICENSE).
