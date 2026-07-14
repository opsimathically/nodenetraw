use std::{net::IpAddr, time::Duration};

/// A snapshot is constructible only after every dump and coherence check passes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SnapshotCompleteness {
    Complete,
}

/// A bounded diagnostic copy of an attribute not interpreted by scanner policy.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnknownAttribute {
    pub kind: u16,
    pub value: Vec<u8>,
}

/// Immutable normalized link identity and scanner-relevant properties.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InterfaceRecord {
    pub index: u32,
    pub name: String,
    pub flags: u32,
    pub link_layer_type: u16,
    pub mtu: Option<u32>,
    pub hardware_address: Vec<u8>,
    pub permanent_hardware_address: Vec<u8>,
    pub controller_index: Option<u32>,
    pub link_index: Option<u32>,
    pub link_netns_id: Option<i32>,
    pub operational_state: Option<u8>,
    pub link_kind: Option<String>,
    pub unknown_attributes: Vec<UnknownAttribute>,
}

/// Immutable normalized IPv4/IPv6 interface address.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AddressRecord {
    pub interface_index: u32,
    pub family: u8,
    pub prefix_length: u8,
    pub scope: u8,
    pub flags: u32,
    pub address: Option<IpAddr>,
    pub local: Option<IpAddr>,
    pub label: Option<String>,
    pub broadcast: Option<IpAddr>,
    pub unknown_attributes: Vec<UnknownAttribute>,
}

/// One typed route metric represented by its stable kernel kind/value pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteMetricRecord {
    pub kind: u16,
    pub value: u32,
}

/// One normalized kernel-selected multipath candidate from a route dump.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteNextHopRecord {
    pub interface_index: u32,
    pub hops: u8,
    pub flags: u8,
    pub gateway: Option<IpAddr>,
    pub unknown_attributes: Vec<UnknownAttribute>,
}

/// Immutable normalized IPv4/IPv6 route record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteRecord {
    pub family: u8,
    pub destination_prefix_length: u8,
    pub source_prefix_length: u8,
    pub destination: Option<IpAddr>,
    pub source: Option<IpAddr>,
    pub table: u32,
    pub route_type: u8,
    pub scope: u8,
    pub protocol: u8,
    pub priority: Option<u32>,
    pub preferred_source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub input_interface: Option<u32>,
    pub output_interface: Option<u32>,
    pub metrics: Vec<RouteMetricRecord>,
    pub multipath: Vec<RouteNextHopRecord>,
    pub has_encapsulation: bool,
    pub unknown_attributes: Vec<UnknownAttribute>,
}

/// Inclusive port or UID range carried by a policy rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InclusiveRange<T> {
    pub start: T,
    pub end: T,
}

/// Immutable normalized policy-routing rule.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RuleRecord {
    pub family: u8,
    pub destination_prefix_length: u8,
    pub source_prefix_length: u8,
    pub destination: Option<IpAddr>,
    pub source: Option<IpAddr>,
    pub table: u32,
    pub action: u8,
    pub priority: Option<u32>,
    pub input_interface: Option<String>,
    pub output_interface: Option<String>,
    pub firewall_mark: Option<u32>,
    pub firewall_mask: Option<u32>,
    pub uid_range: Option<InclusiveRange<u32>>,
    pub ip_protocol: Option<u8>,
    pub source_port_range: Option<InclusiveRange<u16>>,
    pub destination_port_range: Option<InclusiveRange<u16>>,
    pub unknown_attributes: Vec<UnknownAttribute>,
}

/// Immutable normalized ARP/NDP neighbor-cache record.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NeighborRecord {
    pub family: u8,
    pub interface_index: u32,
    pub destination: Option<IpAddr>,
    pub state: u16,
    pub flags: u8,
    pub neighbor_type: u8,
    pub link_layer_address: Vec<u8>,
    pub probes: Option<u32>,
    pub unknown_attributes: Vec<UnknownAttribute>,
}

/// One complete, deterministic view of the descriptor's network namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSnapshot {
    pub generation: u64,
    pub completeness: SnapshotCompleteness,
    pub netns_cookie: Option<u64>,
    pub interfaces: Vec<InterfaceRecord>,
    pub addresses: Vec<AddressRecord>,
    pub routes: Vec<RouteRecord>,
    pub rules: Vec<RuleRecord>,
    pub neighbors: Vec<NeighborRecord>,
}

/// Optional selectors passed to Linux for one policy-aware route lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteQuery {
    pub destination: IpAddr,
    pub source: Option<IpAddr>,
    pub output_interface: Option<u32>,
    pub mark: Option<u32>,
    pub uid: Option<u32>,
    pub ip_protocol: Option<u8>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub deadline: Duration,
}

impl RouteQuery {
    /// Creates a destination-only lookup with a finite two-second deadline.
    #[must_use]
    pub const fn new(destination: IpAddr) -> Self {
        Self {
            destination,
            source: None,
            output_interface: None,
            mark: None,
            uid: None,
            ip_protocol: None,
            source_port: None,
            destination_port: None,
            deadline: Duration::from_secs(2),
        }
    }
}

/// Scanner-relevant classification of a kernel-selected egress path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoutePlanKind {
    Local,
    Loopback,
    EthernetOnLink,
    EthernetGateway,
    Multicast,
}

/// A kernel or snapshot condition that makes a destination unusable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteUnusableReason {
    Unreachable,
    Prohibited,
    BlackHole,
    Throw,
    InterfaceDown,
}

/// An egress form deliberately outside the first portable scanner matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnsupportedRouteReason {
    MissingOutputInterface,
    UnknownOutputInterface(u32),
    LinkLayerType(u16),
    LinkKind(String),
    Encapsulation,
    AmbiguousMultipath,
    MissingIpv6Scope,
}

/// Final usability classification for a generation-bound route lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDisposition {
    Usable(RoutePlanKind),
    Unusable(RouteUnusableReason),
    Unsupported(UnsupportedRouteReason),
}

/// Explicit Linux neighbor-cache interpretation; no entry is created or refreshed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NeighborStatus {
    Missing,
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    NoArp,
    Permanent,
    Unknown(u16),
}

/// One kernel-selected multipath result retained without user-space ECMP choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedNextHop {
    pub interface_index: u32,
    pub gateway: Option<IpAddr>,
    pub hops: u8,
    pub flags: u8,
}

/// A complete route and neighbor plan joined to exactly one snapshot generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    pub generation: u64,
    pub destination: IpAddr,
    pub disposition: RouteDisposition,
    pub route_type: Option<u8>,
    pub table: Option<u32>,
    pub interface_index: Option<u32>,
    pub interface_name: Option<String>,
    pub preferred_source: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub effective_mtu: Option<u32>,
    pub selected_multipath: Option<SelectedNextHop>,
    pub neighbor_status: NeighborStatus,
    pub link_layer_address: Option<Vec<u8>>,
}

/// Result of nonblocking notification processing and possible bounded resync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefreshOutcome {
    Unchanged { generation: u64 },
    Published(NetworkSnapshot),
    Backoff { retry_after: Duration },
}
