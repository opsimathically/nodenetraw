#!/bin/sh
set -eu

if [ "${NODENET_CONTEXT_IN_NAMESPACE:-0}" = "1" ]; then
  ip link set lo up
  ip link add ctx-v0 type veth peer name ctx-v1
  ip link set dev ctx-v0 address 02:00:00:00:19:00
  ip link set dev ctx-v1 address 02:00:00:00:19:01
  ip address add 192.0.2.1/24 dev ctx-v0
  ip -6 address add 2001:db8:19::1/64 dev ctx-v0 nodad
  ip link set ctx-v0 up
  ip link set ctx-v1 up
  ip link add link ctx-v0 name ctx-vlan42 type vlan id 42
  ip address add 198.51.100.1/24 dev ctx-vlan42
  ip link set ctx-vlan42 up
  ip route add blackhole 198.18.19.0/24 table 100
  ip route add prohibit 198.18.20.0/24 table 100
  ip route add unreachable 198.18.21.0/24 table 100
  ip route add 203.0.113.0/24 via 192.0.2.2 dev ctx-v0
  ip route add 203.0.114.0/24 via 192.0.2.4 dev ctx-v0
  ip route add 203.0.115.0/24 via 192.0.2.3 dev ctx-v0 table 100
  ip route add 198.18.30.0/24 \
    nexthop via 192.0.2.2 dev ctx-v0 weight 1 \
    nexthop via 192.0.2.3 dev ctx-v0 weight 1
  ip -6 route add blackhole 2001:db8:100::/64 table 100
  ip rule add priority 1000 from 192.0.2.0/24 table 100
  ip -6 rule add priority 1000 from 2001:db8:19::/64 table 100
  ip neighbor replace 192.0.2.2 lladdr 02:00:00:00:19:01 nud permanent dev ctx-v0
  ip neighbor replace 192.0.2.3 lladdr 02:00:00:00:19:03 nud permanent dev ctx-v0
  ip -6 neighbor replace 2001:db8:19::2 lladdr 02:00:00:00:19:01 nud permanent dev ctx-v0
  ip link add ctx-dummy type dummy
  ip address add 10.20.0.1/24 dev ctx-dummy
  ip link set ctx-dummy up
  if [ -n "${NODENET_CONTEXT_OWNER:-}" ]; then
    runner=$(command -v runuser || true)
    if [ -z "$runner" ]; then
      echo "runuser is required to test as repository owner $NODENET_CONTEXT_OWNER" >&2
      exit 1
    fi
    exec "$runner" -u "$NODENET_CONTEXT_OWNER" -- env \
      HOME="$NODENET_CONTEXT_OWNER_HOME" \
      USER="$NODENET_CONTEXT_OWNER" \
      LOGNAME="$NODENET_CONTEXT_OWNER" \
      CARGO_HOME="$NODENET_CONTEXT_OWNER_HOME/.cargo" \
      RUSTUP_HOME="$NODENET_CONTEXT_OWNER_HOME/.rustup" \
      PATH="$NODENET_CONTEXT_OWNER_HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
      NODENET_CONTEXT_ORACLE_TESTS=1 \
      "$NODENET_CONTEXT_CARGO" test -p nodenet-linux-context \
      namespace_snapshot_matches_ip_json_oracle --locked -- --nocapture --test-threads=1
  fi
  exec env NODENET_CONTEXT_ORACLE_TESTS=1 \
    "$NODENET_CONTEXT_CARGO" test -p nodenet-linux-context \
    namespace_snapshot_matches_ip_json_oracle --locked -- --nocapture --test-threads=1
fi

cargo=${CARGO:-$(command -v cargo)}
if [ "$(id -u)" -eq 0 ]; then
  owner=
  owner_home=
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    owner=$SUDO_USER
    owner_home=$(getent passwd "$owner" | cut -d: -f6)
    cargo="$owner_home/.cargo/bin/cargo"
    if [ -z "$owner_home" ] || [ ! -x "$cargo" ]; then
      echo "could not find the repository owner's Rust toolchain for $owner" >&2
      exit 1
    fi
  fi
  exec unshare --net env \
    NODENET_CONTEXT_IN_NAMESPACE=1 \
    NODENET_CONTEXT_CARGO="$cargo" \
    NODENET_CONTEXT_OWNER="$owner" \
    NODENET_CONTEXT_OWNER_HOME="$owner_home" \
    sh "$0"
fi

exec unshare --user --map-root-user --net env \
  NODENET_CONTEXT_IN_NAMESPACE=1 \
  NODENET_CONTEXT_CARGO="$cargo" \
  sh "$0"
