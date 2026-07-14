#!/bin/sh
set -eu

if [ "${NODENETRAW_IN_NAMESPACE:-0}" = "1" ]; then
  ip link set lo up
  ip link add nr-veth0 type veth peer name nr-veth1
  ip link set dev nr-veth0 address 02:00:00:00:00:01
  ip link set dev nr-veth1 address 02:00:00:00:00:02
  ip address add 192.0.2.1/24 dev nr-veth0
  ip link set nr-veth0 up
  ip link set nr-veth1 up
  node=${NODENETRAW_NODE:-$(command -v node)}
  case "${NODENETRAW_TEST_SUITE:-privileged}" in
    privileged)
      traceroute_topology=0
      router_pid=
      destination_pid=
      cleanup_topology() {
        if [ -n "$destination_pid" ]; then
          kill "$destination_pid" 2>/dev/null || true
          wait "$destination_pid" 2>/dev/null || true
        fi
        if [ -n "$router_pid" ]; then
          kill "$router_pid" 2>/dev/null || true
          wait "$router_pid" 2>/dev/null || true
        fi
        ip link delete nr-tr-src 2>/dev/null || true
      }
      trap cleanup_topology EXIT INT TERM
      if command -v nsenter >/dev/null 2>&1 && command -v unshare >/dev/null 2>&1; then
        self_namespace=$(readlink /proc/self/ns/net)
        unshare --net sh -c 'exec sleep 3600' >/dev/null 2>&1 &
        router_pid=$!
        unshare --net sh -c 'exec sleep 3600' >/dev/null 2>&1 &
        destination_pid=$!
        attempts=0
        while [ "$attempts" -lt 100 ]; do
          router_namespace=$(readlink "/proc/$router_pid/ns/net" 2>/dev/null || true)
          destination_namespace=$(readlink "/proc/$destination_pid/ns/net" 2>/dev/null || true)
          if [ -n "$router_namespace" ] && [ "$router_namespace" != "$self_namespace" ] && \
             [ -n "$destination_namespace" ] && [ "$destination_namespace" != "$self_namespace" ]; then
            break
          fi
          attempts=$((attempts + 1))
          sleep 0.01
        done
        if [ "$attempts" -lt 100 ] && \
           ip link add nr-tr-src type veth peer name nr-tr-r0 && \
           ip link set nr-tr-r0 netns "$router_pid" && \
           ip link add nr-tr-r1 type veth peer name nr-tr-dst && \
           ip link set nr-tr-r1 netns "$router_pid" && \
           ip link set nr-tr-dst netns "$destination_pid" && \
           ip address add 198.18.1.1/24 dev nr-tr-src && \
           ip link set nr-tr-src up && \
           ip route add 198.18.2.0/24 via 198.18.1.2 dev nr-tr-src && \
           ip route add 198.18.3.0/24 via 198.18.1.2 dev nr-tr-src && \
           ip route add 198.18.4.0/24 via 198.18.1.2 dev nr-tr-src && \
           nsenter -t "$router_pid" -n ip link set lo up && \
           nsenter -t "$router_pid" -n ip address add 198.18.1.2/24 dev nr-tr-r0 && \
           nsenter -t "$router_pid" -n ip address add 198.18.2.1/24 dev nr-tr-r1 && \
           nsenter -t "$router_pid" -n ip link set nr-tr-r0 up && \
           nsenter -t "$router_pid" -n ip link set nr-tr-r1 up && \
           nsenter -t "$router_pid" -n sysctl -q -w net.ipv4.ip_forward=1 >/dev/null && \
           nsenter -t "$router_pid" -n ip route add prohibit 198.18.3.0/24 && \
           nsenter -t "$router_pid" -n ip route add blackhole 198.18.4.0/24 && \
           nsenter -t "$destination_pid" -n ip link set lo up && \
           nsenter -t "$destination_pid" -n ip address add 198.18.2.2/24 dev nr-tr-dst && \
           nsenter -t "$destination_pid" -n ip link set nr-tr-dst up && \
           nsenter -t "$destination_pid" -n ip route add 198.18.1.0/24 via 198.18.2.1 dev nr-tr-dst; then
          traceroute_topology=1
        else
          cleanup_topology
          router_pid=
          destination_pid=
        fi
      fi
      test_status=0
      env \
        NODENETRAW_PRIVILEGED_TESTS=1 \
        NODENETRAW_TRACEROUTE_TOPOLOGY="$traceroute_topology" \
        "$node" --test test/privileged.test.mjs || test_status=$?
      exit "$test_status"
      ;;
    event-stress)
      exec "$node" test/phase11-event-stress.mjs
      ;;
    traceroute-stress)
      exec "$node" test/phase15-traceroute-stress.mjs
      ;;
    phase17-protocol)
      exec env NODENETRAW_PROTOCOL_NAMESPACE_TESTS=1 \
        "$node" --test test/phase17-protocol-namespace.test.mjs
      ;;
    *)
      echo "unknown privileged test suite: ${NODENETRAW_TEST_SUITE:-}" >&2
      exit 2
      ;;
  esac
fi

if [ "$(id -u)" -eq 0 ]; then
  exec unshare --net env NODENETRAW_IN_NAMESPACE=1 sh "$0"
fi

exec unshare --user --map-root-user --net \
  env NODENETRAW_IN_NAMESPACE=1 sh "$0"
