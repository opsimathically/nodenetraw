use std::net::IpAddr;

use crate::{
    InterfaceRecord, NeighborRecord, NeighborStatus, NetworkSnapshot, RouteDisposition, RoutePlan,
    RoutePlanKind, RouteRecord, RouteUnusableReason, SelectedNextHop, UnsupportedRouteReason,
};

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_LOOPBACK: u16 = 772;
const IFF_UP: u32 = 1;

/// Joins one kernel-selected route to one immutable snapshot generation.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "early returns keep every route disposition adjacent to its safety predicate"
)]
pub fn plan_route(
    snapshot: &NetworkSnapshot,
    destination: IpAddr,
    route: &RouteRecord,
) -> RoutePlan {
    let unusable = match route.route_type {
        6 => Some(RouteUnusableReason::BlackHole),
        7 => Some(RouteUnusableReason::Unreachable),
        8 => Some(RouteUnusableReason::Prohibited),
        9 => Some(RouteUnusableReason::Throw),
        _ => None,
    };
    if let Some(reason) = unusable {
        return base_plan(
            snapshot.generation,
            destination,
            route,
            RouteDisposition::Unusable(reason),
        );
    }
    if route.has_encapsulation {
        return base_plan(
            snapshot.generation,
            destination,
            route,
            RouteDisposition::Unsupported(UnsupportedRouteReason::Encapsulation),
        );
    }

    let selected = select_multipath(route);
    if !route.multipath.is_empty() && selected.is_none() {
        return base_plan(
            snapshot.generation,
            destination,
            route,
            RouteDisposition::Unsupported(UnsupportedRouteReason::AmbiguousMultipath),
        );
    }
    let interface_index = route
        .output_interface
        .or_else(|| selected.as_ref().map(|value| value.interface_index));
    let Some(interface_index) = interface_index else {
        return base_plan(
            snapshot.generation,
            destination,
            route,
            RouteDisposition::Unsupported(UnsupportedRouteReason::MissingOutputInterface),
        );
    };
    let Some(interface) = snapshot
        .interfaces
        .iter()
        .find(|value| value.index == interface_index)
    else {
        return base_plan(
            snapshot.generation,
            destination,
            route,
            RouteDisposition::Unsupported(UnsupportedRouteReason::UnknownOutputInterface(
                interface_index,
            )),
        );
    };
    if interface.flags & IFF_UP == 0 {
        return detailed_plan(
            snapshot,
            destination,
            route,
            interface,
            selected,
            RouteDisposition::Unusable(RouteUnusableReason::InterfaceDown),
        );
    }
    if destination.is_ipv6()
        && is_ipv6_link_local(destination)
        && route.output_interface.is_none()
        && selected.is_none()
    {
        return detailed_plan(
            snapshot,
            destination,
            route,
            interface,
            selected,
            RouteDisposition::Unsupported(UnsupportedRouteReason::MissingIpv6Scope),
        );
    }

    let kind = if route.route_type == 2 {
        RoutePlanKind::Local
    } else if interface.link_layer_type == ARPHRD_LOOPBACK {
        RoutePlanKind::Loopback
    } else if interface.link_layer_type != ARPHRD_ETHER {
        return detailed_plan(
            snapshot,
            destination,
            route,
            interface,
            selected,
            RouteDisposition::Unsupported(UnsupportedRouteReason::LinkLayerType(
                interface.link_layer_type,
            )),
        );
    } else if let Some(link_kind) = &interface.link_kind
        && !matches!(link_kind.as_str(), "vlan" | "veth")
    {
        return detailed_plan(
            snapshot,
            destination,
            route,
            interface,
            selected,
            RouteDisposition::Unsupported(UnsupportedRouteReason::LinkKind(link_kind.clone())),
        );
    } else if is_multicast(destination) {
        RoutePlanKind::Multicast
    } else if route.gateway.is_some()
        || selected
            .as_ref()
            .is_some_and(|value| value.gateway.is_some())
    {
        RoutePlanKind::EthernetGateway
    } else {
        RoutePlanKind::EthernetOnLink
    };
    detailed_plan(
        snapshot,
        destination,
        route,
        interface,
        selected,
        RouteDisposition::Usable(kind),
    )
}

pub(crate) fn kernel_unusable_plan(
    snapshot: &NetworkSnapshot,
    destination: IpAddr,
    reason: RouteUnusableReason,
) -> RoutePlan {
    RoutePlan {
        generation: snapshot.generation,
        destination,
        disposition: RouteDisposition::Unusable(reason),
        route_type: None,
        table: None,
        interface_index: None,
        interface_name: None,
        preferred_source: None,
        gateway: None,
        next_hop: None,
        effective_mtu: None,
        selected_multipath: None,
        neighbor_status: NeighborStatus::Missing,
        link_layer_address: None,
    }
}

fn detailed_plan(
    snapshot: &NetworkSnapshot,
    destination: IpAddr,
    route: &RouteRecord,
    interface: &InterfaceRecord,
    selected: Option<SelectedNextHop>,
    disposition: RouteDisposition,
) -> RoutePlan {
    let gateway = route
        .gateway
        .or_else(|| selected.as_ref().and_then(|value| value.gateway));
    let next_hop = gateway.or(Some(destination));
    let neighbor = next_hop.and_then(|address| {
        snapshot.neighbors.iter().find(|value| {
            value.interface_index == interface.index && value.destination == Some(address)
        })
    });
    let route_mtu = route
        .metrics
        .iter()
        .find(|value| value.kind == 2)
        .map(|value| value.value)
        .filter(|value| *value != 0);
    let effective_mtu = match (route_mtu, interface.mtu) {
        (Some(route), Some(interface)) => Some(route.min(interface)),
        (route, interface) => route.or(interface),
    };
    RoutePlan {
        generation: snapshot.generation,
        destination,
        disposition,
        route_type: Some(route.route_type),
        table: Some(route.table),
        interface_index: Some(interface.index),
        interface_name: Some(interface.name.clone()),
        preferred_source: route.preferred_source.or(route.source),
        gateway,
        next_hop,
        effective_mtu,
        selected_multipath: selected,
        neighbor_status: neighbor.map_or(NeighborStatus::Missing, neighbor_status),
        link_layer_address: neighbor
            .filter(|value| !value.link_layer_address.is_empty())
            .map(|value| value.link_layer_address.clone()),
    }
}

fn base_plan(
    generation: u64,
    destination: IpAddr,
    route: &RouteRecord,
    disposition: RouteDisposition,
) -> RoutePlan {
    RoutePlan {
        generation,
        destination,
        disposition,
        route_type: Some(route.route_type),
        table: Some(route.table),
        interface_index: route.output_interface,
        interface_name: None,
        preferred_source: route.preferred_source.or(route.source),
        gateway: route.gateway,
        next_hop: route.gateway.or(Some(destination)),
        effective_mtu: route
            .metrics
            .iter()
            .find(|value| value.kind == 2)
            .map(|value| value.value),
        selected_multipath: None,
        neighbor_status: NeighborStatus::Missing,
        link_layer_address: None,
    }
}

fn select_multipath(route: &RouteRecord) -> Option<SelectedNextHop> {
    let mut matches = route.multipath.iter().filter(|value| {
        route
            .output_interface
            .is_none_or(|index| value.interface_index == index)
            && route
                .gateway
                .is_none_or(|gateway| value.gateway == Some(gateway))
    });
    let value = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(SelectedNextHop {
        interface_index: value.interface_index,
        gateway: value.gateway,
        hops: value.hops,
        flags: value.flags,
    })
}

fn neighbor_status(neighbor: &NeighborRecord) -> NeighborStatus {
    match neighbor.state {
        0x01 => NeighborStatus::Incomplete,
        0x02 => NeighborStatus::Reachable,
        0x04 => NeighborStatus::Stale,
        0x08 => NeighborStatus::Delay,
        0x10 => NeighborStatus::Probe,
        0x20 => NeighborStatus::Failed,
        0x40 => NeighborStatus::NoArp,
        0x80 => NeighborStatus::Permanent,
        value => NeighborStatus::Unknown(value),
    }
}

const fn is_multicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => value.is_multicast(),
        IpAddr::V6(value) => value.is_multicast(),
    }
}

const fn is_ipv6_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(value) => (value.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::plan_route;
    use crate::{
        InterfaceRecord, NeighborRecord, NeighborStatus, NetworkSnapshot, RouteDisposition,
        RouteMetricRecord, RouteNextHopRecord, RoutePlanKind, RouteRecord, RouteUnusableReason,
        SnapshotCompleteness, UnsupportedRouteReason,
    };

    #[test]
    fn joins_gateway_neighbor_and_route_mtu_to_one_generation() {
        let mut snapshot = snapshot(41, ethernet());
        snapshot.neighbors.push(neighbor(0x80));
        let mut route = route();
        route.gateway = Some(v4([192, 0, 2, 2]));
        route.preferred_source = Some(v4([192, 0, 2, 1]));
        route.metrics.push(RouteMetricRecord {
            kind: 2,
            value: 1_280,
        });

        let plan = plan_route(&snapshot, v4([203, 0, 113, 7]), &route);
        assert_eq!(plan.generation, 41);
        assert_eq!(plan.table, Some(254));
        assert_eq!(plan.interface_name.as_deref(), Some("eth0"));
        assert_eq!(plan.effective_mtu, Some(1_280));
        assert_eq!(plan.neighbor_status, NeighborStatus::Permanent);
        assert_eq!(plan.link_layer_address, Some(vec![0x02, 0, 0, 0, 0, 2]));
        assert!(matches!(
            plan.disposition,
            RouteDisposition::Usable(RoutePlanKind::EthernetGateway)
        ));

        route.metrics[0].value = 9_000;
        assert_eq!(
            plan_route(&snapshot, v4([203, 0, 113, 7]), &route).effective_mtu,
            Some(1_500)
        );
    }

    #[test]
    fn maps_every_explicit_neighbor_state_without_mutating_it() {
        let cases = [
            (0x01, NeighborStatus::Incomplete),
            (0x02, NeighborStatus::Reachable),
            (0x04, NeighborStatus::Stale),
            (0x08, NeighborStatus::Delay),
            (0x10, NeighborStatus::Probe),
            (0x20, NeighborStatus::Failed),
            (0x40, NeighborStatus::NoArp),
            (0x80, NeighborStatus::Permanent),
            (0x100, NeighborStatus::Unknown(0x100)),
        ];
        for (state, expected) in cases {
            let mut snapshot = snapshot(1, ethernet());
            snapshot.neighbors.push(neighbor(state));
            let mut route = route();
            route.gateway = Some(v4([192, 0, 2, 2]));
            assert_eq!(
                plan_route(&snapshot, v4([203, 0, 113, 7]), &route).neighbor_status,
                expected
            );
        }
        assert_eq!(
            plan_route(&snapshot(1, ethernet()), v4([203, 0, 113, 7]), &route()).neighbor_status,
            NeighborStatus::Missing
        );
    }

    #[test]
    fn preserves_kernel_unusable_route_types() {
        let cases = [
            (6, RouteUnusableReason::BlackHole),
            (7, RouteUnusableReason::Unreachable),
            (8, RouteUnusableReason::Prohibited),
            (9, RouteUnusableReason::Throw),
        ];
        for (route_type, expected) in cases {
            let mut route = route();
            route.route_type = route_type;
            assert_eq!(
                plan_route(&snapshot(1, ethernet()), v4([198, 51, 100, 1]), &route).disposition,
                RouteDisposition::Unusable(expected)
            );
        }
    }

    #[test]
    fn rejects_down_non_ethernet_tunnel_and_encapsulation_plans() {
        let mut down = ethernet();
        down.flags = 0;
        assert_eq!(
            plan_route(&snapshot(1, down), v4([192, 0, 2, 9]), &route()).disposition,
            RouteDisposition::Unusable(RouteUnusableReason::InterfaceDown)
        );

        let mut non_ethernet = ethernet();
        non_ethernet.link_layer_type = 512;
        assert_eq!(
            plan_route(&snapshot(1, non_ethernet), v4([192, 0, 2, 9]), &route()).disposition,
            RouteDisposition::Unsupported(UnsupportedRouteReason::LinkLayerType(512))
        );

        let mut tunnel = ethernet();
        tunnel.link_kind = Some("wireguard".into());
        assert_eq!(
            plan_route(&snapshot(1, tunnel), v4([192, 0, 2, 9]), &route()).disposition,
            RouteDisposition::Unsupported(UnsupportedRouteReason::LinkKind("wireguard".into()))
        );

        let mut encapsulated = route();
        encapsulated.has_encapsulation = true;
        assert_eq!(
            plan_route(&snapshot(1, ethernet()), v4([192, 0, 2, 9]), &encapsulated).disposition,
            RouteDisposition::Unsupported(UnsupportedRouteReason::Encapsulation)
        );
    }

    #[test]
    fn accepts_vlan_loopback_local_and_multicast_plans() {
        let mut vlan = ethernet();
        vlan.link_kind = Some("vlan".into());
        assert!(matches!(
            plan_route(&snapshot(1, vlan), v4([224, 0, 0, 1]), &route()).disposition,
            RouteDisposition::Usable(RoutePlanKind::Multicast)
        ));

        let mut loopback = ethernet();
        loopback.name = "lo".into();
        loopback.link_layer_type = 772;
        assert!(matches!(
            plan_route(
                &snapshot(1, loopback.clone()),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                &route()
            )
            .disposition,
            RouteDisposition::Usable(RoutePlanKind::Loopback)
        ));

        let mut local = route();
        local.route_type = 2;
        assert!(matches!(
            plan_route(&snapshot(1, loopback), v4([127, 0, 0, 1]), &local).disposition,
            RouteDisposition::Usable(RoutePlanKind::Local)
        ));
    }

    #[test]
    fn retains_only_a_kernel_identified_multipath_selection() {
        let mut route = route();
        route.output_interface = None;
        route.multipath = vec![next_hop(7, [192, 0, 2, 2]), next_hop(8, [192, 0, 2, 3])];
        assert_eq!(
            plan_route(&snapshot(1, ethernet()), v4([198, 18, 0, 1]), &route).disposition,
            RouteDisposition::Unsupported(UnsupportedRouteReason::AmbiguousMultipath)
        );

        route.multipath = vec![next_hop(8, [192, 0, 2, 3])];
        route.output_interface = Some(7);
        assert_eq!(
            plan_route(&snapshot(1, ethernet()), v4([198, 18, 0, 1]), &route).disposition,
            RouteDisposition::Unsupported(UnsupportedRouteReason::AmbiguousMultipath)
        );

        route.multipath = vec![next_hop(7, [192, 0, 2, 2]), next_hop(8, [192, 0, 2, 3])];
        route.output_interface = Some(7);
        route.gateway = Some(v4([192, 0, 2, 2]));
        let plan = plan_route(&snapshot(1, ethernet()), v4([198, 18, 0, 1]), &route);
        assert_eq!(plan.selected_multipath.unwrap().interface_index, 7);
        assert_eq!(plan.gateway, Some(v4([192, 0, 2, 2])));
    }

    fn snapshot(generation: u64, interface: InterfaceRecord) -> NetworkSnapshot {
        NetworkSnapshot {
            generation,
            completeness: SnapshotCompleteness::Complete,
            netns_cookie: Some(7),
            interfaces: vec![interface],
            addresses: Vec::new(),
            routes: Vec::new(),
            rules: Vec::new(),
            neighbors: Vec::new(),
        }
    }

    fn ethernet() -> InterfaceRecord {
        InterfaceRecord {
            index: 7,
            name: "eth0".into(),
            flags: 1,
            link_layer_type: 1,
            mtu: Some(1_500),
            hardware_address: vec![0x02, 0, 0, 0, 0, 1],
            permanent_hardware_address: Vec::new(),
            controller_index: None,
            link_index: None,
            link_netns_id: None,
            operational_state: Some(6),
            link_kind: None,
            unknown_attributes: Vec::new(),
        }
    }

    fn route() -> RouteRecord {
        RouteRecord {
            family: 2,
            destination_prefix_length: 32,
            source_prefix_length: 0,
            destination: None,
            source: None,
            table: 254,
            route_type: 1,
            scope: 0,
            protocol: 0,
            priority: None,
            preferred_source: None,
            gateway: None,
            input_interface: None,
            output_interface: Some(7),
            metrics: Vec::new(),
            multipath: Vec::new(),
            has_encapsulation: false,
            unknown_attributes: Vec::new(),
        }
    }

    fn neighbor(state: u16) -> NeighborRecord {
        NeighborRecord {
            family: 2,
            interface_index: 7,
            destination: Some(v4([192, 0, 2, 2])),
            state,
            flags: 0,
            neighbor_type: 1,
            link_layer_address: vec![0x02, 0, 0, 0, 0, 2],
            probes: None,
            unknown_attributes: Vec::new(),
        }
    }

    fn next_hop(interface_index: u32, gateway: [u8; 4]) -> RouteNextHopRecord {
        RouteNextHopRecord {
            interface_index,
            hops: 0,
            flags: 0,
            gateway: Some(v4(gateway)),
            unknown_attributes: Vec::new(),
        }
    }

    fn v4(octets: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(octets))
    }
}
