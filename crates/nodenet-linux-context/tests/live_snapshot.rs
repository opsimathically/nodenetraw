use std::collections::BTreeSet;
use std::process::Command;
use std::time::Duration;

use nodenet_linux_context::{
    IncompleteReason, NeighborStatus, RefreshOutcome, RouteContext, RouteContextDriver,
    RouteDisposition, RoutePlanKind, RouteQuery, RouteUnusableReason, SnapshotCompleteness,
    SnapshotError, UnsupportedRouteReason,
};

#[test]
fn live_snapshot_is_complete_sorted_and_coherent() {
    let mut context = RouteContext::new().expect("route context should open without privileges");
    let snapshot = context
        .snapshot()
        .expect("the current network namespace should produce a complete snapshot");

    assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
    assert_eq!(snapshot.generation, 1);
    assert!(snapshot.interfaces.iter().any(|link| link.name == "lo"));
    assert!(
        snapshot
            .interfaces
            .windows(2)
            .all(|pair| pair[0] <= pair[1])
    );
    assert!(snapshot.addresses.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(snapshot.routes.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(snapshot.rules.windows(2).all(|pair| pair[0] <= pair[1]));
    assert!(snapshot.neighbors.windows(2).all(|pair| pair[0] <= pair[1]));

    let interfaces: BTreeSet<u32> = snapshot.interfaces.iter().map(|link| link.index).collect();
    assert!(
        snapshot
            .addresses
            .iter()
            .all(|address| interfaces.contains(&address.interface_index))
    );
    assert!(snapshot.routes.iter().all(|route| {
        route
            .input_interface
            .into_iter()
            .chain(route.output_interface)
            .chain(route.multipath.iter().map(|hop| hop.interface_index))
            .all(|index| interfaces.contains(&index))
    }));
    assert!(
        snapshot
            .neighbors
            .iter()
            .all(|neighbor| interfaces.contains(&neighbor.interface_index))
    );

    let next = context
        .snapshot()
        .expect("a second complete snapshot should use the same descriptor");
    assert_eq!(next.generation, 2);
    assert_eq!(next.netns_cookie, snapshot.netns_cookie);
}

#[test]
fn repeated_snapshots_do_not_leak_descriptors() {
    let mut context = RouteContext::new().expect("route context should open");
    let descriptors_with_context = descriptor_count();

    for _ in 0..16 {
        context
            .snapshot()
            .expect("repeated snapshot should complete");
    }
    // Other tests in this binary may close descriptors concurrently, so a decrease
    // is harmless; retained descriptors would make this count grow.
    assert!(descriptor_count() <= descriptors_with_context);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the namespace oracle keeps one topology's snapshot, route, and change assertions together"
)]
fn namespace_snapshot_matches_ip_json_oracle() {
    if std::env::var_os("NODENET_CONTEXT_ORACLE_TESTS").is_none() {
        return;
    }
    let mut context = RouteContext::new().expect("namespace route context should open");
    let snapshot = context
        .snapshot()
        .expect("namespace snapshot should complete");

    assert!(snapshot.interfaces.iter().any(|link| link.name == "ctx-v0"));
    assert!(
        snapshot
            .interfaces
            .iter()
            .any(|link| link.name == "ctx-vlan42")
    );
    assert!(snapshot.addresses.iter().any(|address| {
        address
            .address
            .is_some_and(|value| value.to_string() == "192.0.2.1")
    }));
    assert!(snapshot.routes.iter().any(|route| route.table == 100));
    assert!(snapshot.rules.iter().any(|rule| rule.table == 100));
    assert!(snapshot.neighbors.iter().any(|neighbor| {
        neighbor
            .destination
            .is_some_and(|value| value.to_string() == "192.0.2.2")
    }));

    let link_json = ip_json(&["link", "show"]);
    assert_eq!(
        snapshot.interfaces.len(),
        occurrences(&link_json, "\"ifindex\":")
    );

    let address_json = ip_json(&["address", "show"]);
    assert_eq!(
        snapshot.addresses.len(),
        occurrences(&address_json, "\"family\":\"inet\"")
            + occurrences(&address_json, "\"family\":\"inet6\"")
    );

    let route4_json = ip_json(&["-4", "route", "show", "table", "all"]);
    let route6_json = ip_json(&["-6", "route", "show", "table", "all"]);
    assert_eq!(
        snapshot.routes.len(),
        occurrences(&route4_json, "\"dst\":") + occurrences(&route6_json, "\"dst\":")
    );

    let neighbor4_json = ip_json(&["-4", "neighbor", "show", "nud", "all"]);
    let neighbor6_json = ip_json(&["-6", "neighbor", "show", "nud", "all"]);
    assert_eq!(
        snapshot.neighbors.len(),
        occurrences(&neighbor4_json, "\"dst\":") + occurrences(&neighbor6_json, "\"dst\":")
    );

    let next = context
        .snapshot()
        .expect("stable namespace should resnapshot");
    assert_eq!(next.interfaces, snapshot.interfaces);
    assert_eq!(next.addresses, snapshot.addresses);
    assert_eq!(next.routes, snapshot.routes);
    assert_eq!(next.rules, snapshot.rules);
    assert_eq!(next.neighbors, snapshot.neighbors);

    let gateway = context
        .resolve_route(&RouteQuery::new("203.0.113.7".parse().unwrap()), None)
        .expect("gateway route should resolve");
    assert_eq!(gateway.table, Some(254));
    assert_eq!(gateway.gateway, Some("192.0.2.2".parse().unwrap()));
    assert_eq!(gateway.neighbor_status, NeighborStatus::Permanent);
    assert!(matches!(
        gateway.disposition,
        RouteDisposition::Usable(RoutePlanKind::EthernetGateway)
    ));

    let missing_neighbor = context
        .resolve_route(&RouteQuery::new("203.0.114.7".parse().unwrap()), None)
        .expect("route with missing neighbor should still resolve");
    assert_eq!(missing_neighbor.neighbor_status, NeighborStatus::Missing);
    assert!(missing_neighbor.link_layer_address.is_none());

    let mut policy_query = RouteQuery::new("203.0.115.7".parse().unwrap());
    policy_query.source = Some("192.0.2.1".parse().unwrap());
    policy_query.ip_protocol = Some(6);
    policy_query.source_port = Some(40_000);
    policy_query.destination_port = Some(443);
    let policy = context
        .resolve_route(&policy_query, None)
        .expect("source policy route should resolve through table 100");
    assert_eq!(policy.table, Some(100));
    assert_eq!(policy.gateway, Some("192.0.2.3".parse().unwrap()));

    let on_link = context
        .resolve_route(&RouteQuery::new("198.51.100.2".parse().unwrap()), None)
        .expect("VLAN on-link route should resolve");
    assert_eq!(on_link.interface_name.as_deref(), Some("ctx-vlan42"));
    assert!(matches!(
        on_link.disposition,
        RouteDisposition::Usable(RoutePlanKind::EthernetOnLink)
    ));

    let mut blackhole_query = RouteQuery::new("198.18.19.1".parse().unwrap());
    blackhole_query.source = Some("192.0.2.1".parse().unwrap());
    assert!(matches!(
        context
            .resolve_route(&blackhole_query, None)
            .unwrap()
            .disposition,
        RouteDisposition::Unusable(RouteUnusableReason::BlackHole)
    ));
    let mut prohibit_query = RouteQuery::new("198.18.20.1".parse().unwrap());
    prohibit_query.source = blackhole_query.source;
    assert!(matches!(
        context
            .resolve_route(&prohibit_query, None)
            .unwrap()
            .disposition,
        RouteDisposition::Unusable(RouteUnusableReason::Prohibited)
    ));
    let mut unreachable_query = RouteQuery::new("198.18.21.1".parse().unwrap());
    unreachable_query.source = blackhole_query.source;
    assert!(matches!(
        context
            .resolve_route(&unreachable_query, None)
            .unwrap()
            .disposition,
        RouteDisposition::Unusable(RouteUnusableReason::Unreachable)
    ));

    let mut ecmp_query = RouteQuery::new("198.18.30.1".parse().unwrap());
    ecmp_query.ip_protocol = Some(17);
    ecmp_query.source_port = Some(53_000);
    ecmp_query.destination_port = Some(53);
    let ecmp = context
        .resolve_route(&ecmp_query, None)
        .expect("kernel should choose one ECMP path");
    assert!(matches!(
        ecmp.gateway.map(|value| value.to_string()).as_deref(),
        Some("192.0.2.2" | "192.0.2.3")
    ));

    let unsupported = context
        .resolve_route(&RouteQuery::new("10.20.0.2".parse().unwrap()), None)
        .expect("dummy route should produce a structured unsupported plan");
    assert!(matches!(
        unsupported.disposition,
        RouteDisposition::Unsupported(UnsupportedRouteReason::LinkKind(ref kind)) if kind == "dummy"
    ));

    if ip(&["address", "add", "192.0.2.99/24", "dev", "ctx-v0"]) {
        let previous_generation = context.current_snapshot().unwrap().generation;
        let refreshed = context
            .refresh()
            .expect("address notification should apply");
        assert!(matches!(refreshed, RefreshOutcome::Published(_)));
        let refreshed = context.current_snapshot().unwrap();
        assert!(refreshed.generation > previous_generation);
        assert!(refreshed.addresses.iter().any(|address| {
            address
                .address
                .is_some_and(|value| value.to_string() == "192.0.2.99")
        }));
        assert!(ip(&["address", "del", "192.0.2.99/24", "dev", "ctx-v0"]));
        assert!(matches!(
            context.refresh().unwrap(),
            RefreshOutcome::Published(_)
        ));
    }

    let changer = std::thread::spawn(|| {
        for last_octet in 100..108 {
            let address = format!("192.0.2.{last_octet}/24");
            assert!(ip(&["address", "add", &address, "dev", "ctx-v0"]));
            assert!(ip(&["address", "del", &address, "dev", "ctx-v0"]));
        }
    });
    let mut coherent_results = 0;
    for _ in 0..32 {
        match context.resolve_route(&RouteQuery::new("203.0.113.7".parse().unwrap()), None) {
            Ok(plan) => {
                assert_eq!(
                    plan.generation,
                    context.current_snapshot().unwrap().generation
                );
                coherent_results += 1;
            }
            Err(SnapshotError::Incomplete {
                reason: IncompleteReason::GenerationChanged,
                attempts: 3,
            }) => {}
            Err(error) => panic!("unexpected route-race failure: {error}"),
        }
    }
    changer.join().unwrap();
    context.refresh().unwrap();
    assert!(coherent_results > 0);

    assert!(ip(&[
        "neighbor",
        "replace",
        "192.0.2.3",
        "nud",
        "failed",
        "dev",
        "ctx-v0"
    ]));
    context.refresh().unwrap();
    let failed_neighbor = context
        .resolve_route(&policy_query, None)
        .expect("failed neighbor state should remain a usable route fact");
    assert_eq!(failed_neighbor.neighbor_status, NeighborStatus::Failed);
    assert!(failed_neighbor.link_layer_address.is_none());

    assert!(ip(&["link", "set", "ctx-v0", "down"]));
    context.refresh().unwrap();
    let down = context
        .resolve_route(&RouteQuery::new("203.0.113.7".parse().unwrap()), None)
        .expect("a down egress should be classified rather than guessed");
    assert!(matches!(
        down.disposition,
        RouteDisposition::Unusable(
            RouteUnusableReason::InterfaceDown | RouteUnusableReason::Unreachable
        )
    ));
}

#[test]
fn repeated_snapshot_rss_is_bounded() {
    if std::env::var_os("NODENET_CONTEXT_STRESS_TESTS").is_none() {
        return;
    }
    let mut context = RouteContext::new().expect("stress context should open");
    for _ in 0..32 {
        context
            .snapshot()
            .expect("warm-up snapshot should complete");
    }
    let baseline = resident_bytes();
    for _ in 0..512 {
        context.snapshot().expect("stress snapshot should complete");
    }
    let growth = resident_bytes().saturating_sub(baseline);
    assert!(
        growth <= 8 * 1_048_576,
        "resident growth was {growth} bytes"
    );
}

#[test]
fn live_kernel_route_queries_are_generation_bound() {
    let mut context = RouteContext::new().expect("route context should open");
    let snapshot = context
        .snapshot()
        .expect("initial snapshot should complete");
    let ipv4 = context
        .resolve_route(&RouteQuery::new("127.0.0.1".parse().unwrap()), None)
        .expect("IPv4 loopback should resolve");
    assert_eq!(ipv4.generation, snapshot.generation);
    assert!(matches!(
        ipv4.disposition,
        RouteDisposition::Usable(RoutePlanKind::Local | RoutePlanKind::Loopback)
    ));
    assert_eq!(ipv4.interface_name.as_deref(), Some("lo"));

    let ipv6 = context
        .resolve_route(&RouteQuery::new("::1".parse().unwrap()), None)
        .expect("IPv6 loopback should resolve");
    assert!(
        matches!(
            ipv6.disposition,
            RouteDisposition::Usable(RoutePlanKind::Local | RoutePlanKind::Loopback)
        ),
        "unexpected IPv6 loopback plan: {ipv6:?}"
    );
    assert_eq!(ipv6.interface_name.as_deref(), Some("lo"));
}

#[test]
fn asynchronous_context_driver_owns_one_serialized_context() {
    let driver = RouteContextDriver::new().expect("route context driver should start");
    let refreshed = driver
        .refresh(Duration::from_secs(2))
        .unwrap()
        .wait()
        .expect("background refresh should complete");
    let generation = match refreshed {
        RefreshOutcome::Published(snapshot) => snapshot.generation,
        RefreshOutcome::Unchanged { generation } => generation,
        RefreshOutcome::Backoff { .. } => panic!("initial refresh cannot be in backoff"),
    };
    let plan = driver
        .resolve_route(RouteQuery::new("127.0.0.1".parse().unwrap()))
        .unwrap()
        .wait()
        .expect("background loopback query should complete");
    assert_eq!(plan.generation, generation);
    assert_eq!(plan.interface_name.as_deref(), Some("lo"));
}

#[test]
fn phase20_stress_queries_cancellation_and_driver_cleanup_are_bounded() {
    if std::env::var_os("NODENET_CONTEXT_PHASE20_STRESS_TESTS").is_none() {
        return;
    }
    let mut context = RouteContext::new().expect("stress route context should open");
    context.snapshot().expect("stress snapshot should complete");
    let query = RouteQuery::new("127.0.0.1".parse().unwrap());
    for _ in 0..32 {
        context
            .resolve_route(&query, None)
            .expect("warm-up route query should complete");
    }
    let descriptors = descriptor_count();
    let baseline = resident_bytes();
    for _ in 0..1_024 {
        let plan = context
            .resolve_route(&query, None)
            .expect("repeated route query should complete");
        assert_eq!(
            plan.generation,
            context.current_snapshot().unwrap().generation
        );
    }
    for _ in 0..32 {
        let driver = RouteContextDriver::new().expect("stress driver should start");
        driver
            .resolve_route(query.clone())
            .unwrap()
            .wait()
            .expect("driver route query should complete");
    }
    assert!(descriptor_count() <= descriptors);
    let growth = resident_bytes().saturating_sub(baseline);
    assert!(
        growth <= 16 * 1_048_576,
        "phase 20 resident growth was {growth} bytes"
    );
}

fn descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("Linux procfs is available to the test oracle")
        .count()
}

fn ip_json(arguments: &[&str]) -> String {
    let output = Command::new("ip")
        .arg("-j")
        .args(arguments)
        .output()
        .expect("iproute2 is required by the opt-in oracle test");
    assert!(output.status.success(), "ip oracle command failed");
    String::from_utf8(output.stdout).expect("ip -j output should be UTF-8 JSON")
}

fn ip(arguments: &[&str]) -> bool {
    Command::new("ip")
        .args(arguments)
        .status()
        .is_ok_and(|status| status.success())
}

fn occurrences(input: &str, needle: &str) -> usize {
    input.match_indices(needle).count()
}

fn resident_bytes() -> usize {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("Linux procfs is available to the stress-test oracle");
    let line = status
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .expect("VmRSS should be present");
    let kib = line
        .split_ascii_whitespace()
        .nth(1)
        .expect("VmRSS should contain a value")
        .parse::<usize>()
        .expect("VmRSS should be numeric");
    kib * 1024
}
