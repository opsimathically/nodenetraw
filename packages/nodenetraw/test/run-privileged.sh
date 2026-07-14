#!/bin/sh
set -eu

package_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repository_root=$(CDPATH= cd -- "$package_root/../.." && pwd)
cd "$package_root"

mode=${1:-}
suite=${2:-privileged}
case "$mode" in
  root|namespace) ;;
  *)
    echo "usage: sh test/run-privileged.sh root|namespace [privileged|event-stress|traceroute-stress]" >&2
    exit 2
    ;;
esac
case "$suite" in
  privileged|event-stress|traceroute-stress) ;;
  *)
    echo "unknown privileged test suite: $suite" >&2
    exit 2
    ;;
esac

is_supported_node() {
  [ -x "$1" ] || return 1
  major=$("$1" -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null) || return 1
  [ "$major" -ge 26 ] 2>/dev/null
}

find_node() {
  home=$1
  if [ -n "${NODENETRAW_NODE:-}" ] && is_supported_node "$NODENETRAW_NODE"; then
    printf '%s\n' "$NODENETRAW_NODE"
    return
  fi

  requested=$(sed -n '1p' "$repository_root/.nvmrc" 2>/dev/null || true)
  if [ -n "$requested" ] && [ -d "$home/.nvm/versions/node" ]; then
    candidate=$(find "$home/.nvm/versions/node" -path "*/v${requested}*/bin/node" -type f 2>/dev/null | sort -V | tail -n 1)
    if [ -n "$candidate" ] && is_supported_node "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  fi

  for candidate in \
    "$home/.volta/bin/node" \
    "$home/.local/share/mise/shims/node" \
    /usr/local/bin/node \
    /usr/bin/node
  do
    if is_supported_node "$candidate"; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  echo "could not find Node.js 26+ for ${SUDO_USER:-the current user}; set NODENETRAW_NODE to its absolute path" >&2
  exit 1
}

run_build_as_owner() {
  owner=$1
  home=$2
  node=$3
  node_bin=$(dirname "$node")
  npm="$node_bin/npm"
  if [ ! -x "$npm" ]; then
    echo "could not find npm beside $node" >&2
    exit 1
  fi
  runner=$(command -v runuser || true)
  if [ -z "$runner" ]; then
    echo "runuser is required to build as repository owner $owner" >&2
    exit 1
  fi
  "$runner" -u "$owner" -- env \
    HOME="$home" \
    USER="$owner" \
    LOGNAME="$owner" \
    CARGO_HOME="$home/.cargo" \
    RUSTUP_HOME="$home/.rustup" \
    PATH="$node_bin:$home/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    "$npm" run build
}

if [ "$(id -u)" -eq 0 ]; then
  owner=${SUDO_USER:-$(stat -c %U "$repository_root")}
  if [ "$owner" != root ]; then
    owner_entry=$(getent passwd "$owner" || true)
    if [ -z "$owner_entry" ]; then
      echo "could not resolve repository owner $owner" >&2
      exit 1
    fi
    owner_home=$(printf '%s\n' "$owner_entry" | cut -d: -f6)
    node=$(find_node "$owner_home")
    run_build_as_owner "$owner" "$owner_home" "$node"
  else
    node=$(find_node "${HOME:-/root}")
    npm run build
  fi
else
  if [ "$mode" = root ]; then
    echo "this test suite requires root; rerun the npm command with sudo" >&2
    exit 1
  fi
  node=$(command -v node)
  if ! is_supported_node "$node"; then
    echo "test:namespace requires Node.js 26+" >&2
    exit 1
  fi
  npm run build
fi

node_bin=$(dirname "$node")
exec env \
  NODENETRAW_NODE="$node" \
  NODENETRAW_TEST_SUITE="$suite" \
  PATH="$node_bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  sh test/run-namespace.sh
