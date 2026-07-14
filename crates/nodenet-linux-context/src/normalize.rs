use std::{collections::BTreeSet, net::IpAddr};

use netlink_packet_core::{DefaultNla, Nla};
use netlink_packet_route::{
    RouteNetlinkMessage,
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkInfo, LinkMessage},
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage, RouteMetric, RouteNextHop, RouteType},
    rule::{RuleAttribute, RuleMessage},
};

use crate::{
    AddressRecord, InclusiveRange, IncompleteReason, InterfaceRecord, MAX_ADDRESSES,
    MAX_INTERFACES, MAX_LINK_LAYER_ADDRESS_BYTES, MAX_MULTIPATH_NEXT_HOPS, MAX_NEIGHBORS,
    MAX_ROUTES, MAX_RULES, MAX_SNAPSHOT_UNKNOWN_BYTES, MAX_STRING_ATTRIBUTE_BYTES,
    MAX_UNKNOWN_ATTRIBUTE_BYTES, NeighborRecord, NetworkSnapshot, RouteMetricRecord,
    RouteNextHopRecord, RouteRecord, RuleRecord, SnapshotError, SnapshotResource, UnknownAttribute,
    decoder::BufferedNotification,
};

#[derive(Default)]
pub(crate) struct NormalizedParts {
    pub(crate) interfaces: Vec<InterfaceRecord>,
    pub(crate) addresses: Vec<AddressRecord>,
    pub(crate) routes: Vec<RouteRecord>,
    pub(crate) rules: Vec<RuleRecord>,
    pub(crate) neighbors: Vec<NeighborRecord>,
    unknown_bytes: usize,
}

impl NormalizedParts {
    pub(crate) fn from_snapshot(snapshot: NetworkSnapshot) -> Result<Self, SnapshotError> {
        let mut parts = Self {
            interfaces: snapshot.interfaces,
            addresses: snapshot.addresses,
            routes: snapshot.routes,
            rules: snapshot.rules,
            neighbors: snapshot.neighbors,
            unknown_bytes: 0,
        };
        parts.recompute_unknown_bytes()?;
        Ok(parts)
    }

    pub(crate) fn push_messages(
        &mut self,
        messages: Vec<RouteNetlinkMessage>,
    ) -> Result<(), SnapshotError> {
        for message in messages {
            match message {
                RouteNetlinkMessage::NewLink(message) => {
                    let record = normalize_link(message, &mut 0)?;
                    push_bounded(
                        &mut self.interfaces,
                        record,
                        MAX_INTERFACES,
                        SnapshotResource::Interfaces,
                    )?;
                }
                RouteNetlinkMessage::NewAddress(message) => {
                    let record = normalize_address(message, &mut 0)?;
                    push_bounded(
                        &mut self.addresses,
                        record,
                        MAX_ADDRESSES,
                        SnapshotResource::Addresses,
                    )?;
                }
                RouteNetlinkMessage::NewRoute(message) => {
                    let record = normalize_route(message, &mut self.unknown_bytes)?;
                    push_bounded(
                        &mut self.routes,
                        record,
                        MAX_ROUTES,
                        SnapshotResource::Routes,
                    )?;
                }
                RouteNetlinkMessage::NewRule(message) => {
                    let record = normalize_rule(message, &mut self.unknown_bytes)?;
                    push_bounded(&mut self.rules, record, MAX_RULES, SnapshotResource::Rules)?;
                }
                RouteNetlinkMessage::NewNeighbour(message) => {
                    let record = normalize_neighbor(message, &mut self.unknown_bytes)?;
                    push_bounded(
                        &mut self.neighbors,
                        record,
                        MAX_NEIGHBORS,
                        SnapshotResource::Neighbors,
                    )?;
                }
                _ => {
                    return Err(SnapshotError::incomplete(
                        IncompleteReason::UnexpectedMessage,
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Self, SnapshotError> {
        self.interfaces.sort();
        self.addresses.sort();
        self.routes.sort();
        self.rules.sort();
        self.neighbors.sort();
        let interface_indices: BTreeSet<u32> =
            self.interfaces.iter().map(|record| record.index).collect();
        for interface in &self.interfaces {
            validate_reference(interface.controller_index, &interface_indices)?;
            if interface.link_netns_id.is_none() && interface.link_index != Some(interface.index) {
                validate_reference(interface.link_index, &interface_indices)?;
            }
        }
        for address in &self.addresses {
            validate_reference(Some(address.interface_index), &interface_indices)?;
        }
        for route in &self.routes {
            validate_reference(route.input_interface, &interface_indices)?;
            validate_reference(route.output_interface, &interface_indices)?;
            for next_hop in &route.multipath {
                validate_reference(Some(next_hop.interface_index), &interface_indices)?;
            }
        }
        for neighbor in &self.neighbors {
            validate_reference(Some(neighbor.interface_index), &interface_indices)?;
        }
        Ok(self)
    }

    pub(crate) fn apply_notifications(
        &mut self,
        notifications: Vec<BufferedNotification>,
    ) -> Result<(), SnapshotError> {
        for notification in notifications {
            match notification.message {
                RouteNetlinkMessage::NewLink(message) => {
                    let record = normalize_link(message, &mut self.unknown_bytes)?;
                    self.interfaces.retain(|value| value.index != record.index);
                    push_bounded(
                        &mut self.interfaces,
                        record,
                        MAX_INTERFACES,
                        SnapshotResource::Interfaces,
                    )?;
                }
                RouteNetlinkMessage::DelLink(message) => {
                    self.interfaces
                        .retain(|value| value.index != message.header.index);
                }
                RouteNetlinkMessage::NewAddress(message) => {
                    let record = normalize_address(message, &mut self.unknown_bytes)?;
                    self.addresses.retain(|value| !same_address(value, &record));
                    push_bounded(
                        &mut self.addresses,
                        record,
                        MAX_ADDRESSES,
                        SnapshotResource::Addresses,
                    )?;
                }
                RouteNetlinkMessage::DelAddress(message) => {
                    let record = normalize_address(message, &mut 0)?;
                    self.addresses.retain(|value| !same_address(value, &record));
                }
                RouteNetlinkMessage::NewRoute(message) => {
                    let record = normalize_route(message, &mut 0)?;
                    self.routes.retain(|value| !same_route(value, &record));
                    push_bounded(
                        &mut self.routes,
                        record,
                        MAX_ROUTES,
                        SnapshotResource::Routes,
                    )?;
                }
                RouteNetlinkMessage::DelRoute(message) => {
                    let record = normalize_route(message, &mut 0)?;
                    self.routes.retain(|value| !same_route(value, &record));
                }
                RouteNetlinkMessage::NewRule(message) => {
                    let record = normalize_rule(message, &mut 0)?;
                    self.rules.retain(|value| !same_rule(value, &record));
                    push_bounded(&mut self.rules, record, MAX_RULES, SnapshotResource::Rules)?;
                }
                RouteNetlinkMessage::DelRule(message) => {
                    let record = normalize_rule(message, &mut 0)?;
                    self.rules.retain(|value| !same_rule(value, &record));
                }
                RouteNetlinkMessage::NewNeighbour(message) => {
                    let record = normalize_neighbor(message, &mut 0)?;
                    self.neighbors
                        .retain(|value| !same_neighbor(value, &record));
                    push_bounded(
                        &mut self.neighbors,
                        record,
                        MAX_NEIGHBORS,
                        SnapshotResource::Neighbors,
                    )?;
                }
                RouteNetlinkMessage::DelNeighbour(message) => {
                    let record = normalize_neighbor(message, &mut 0)?;
                    self.neighbors
                        .retain(|value| !same_neighbor(value, &record));
                }
                _ => {
                    return Err(SnapshotError::incomplete(
                        IncompleteReason::UnexpectedMessage,
                    ));
                }
            }
            self.recompute_unknown_bytes()?;
        }
        Ok(())
    }

    fn recompute_unknown_bytes(&mut self) -> Result<(), SnapshotError> {
        let attributes = self
            .interfaces
            .iter()
            .flat_map(|value| &value.unknown_attributes)
            .chain(
                self.addresses
                    .iter()
                    .flat_map(|value| &value.unknown_attributes),
            )
            .chain(
                self.routes
                    .iter()
                    .flat_map(|value| &value.unknown_attributes),
            )
            .chain(
                self.routes
                    .iter()
                    .flat_map(|value| &value.multipath)
                    .flat_map(|value| &value.unknown_attributes),
            )
            .chain(
                self.rules
                    .iter()
                    .flat_map(|value| &value.unknown_attributes),
            )
            .chain(
                self.neighbors
                    .iter()
                    .flat_map(|value| &value.unknown_attributes),
            )
            .map(|value| value.value.len());
        let mut total = 0_usize;
        for length in attributes {
            total = total
                .checked_add(length)
                .ok_or(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::SnapshotUnknownBytes,
                    actual: usize::MAX,
                    maximum: MAX_SNAPSHOT_UNKNOWN_BYTES,
                })?;
            if total > MAX_SNAPSHOT_UNKNOWN_BYTES {
                return Err(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::SnapshotUnknownBytes,
                    actual: total,
                    maximum: MAX_SNAPSHOT_UNKNOWN_BYTES,
                });
            }
        }
        self.unknown_bytes = total;
        Ok(())
    }
}

fn same_address(left: &AddressRecord, right: &AddressRecord) -> bool {
    left.interface_index == right.interface_index
        && left.family == right.family
        && left.prefix_length == right.prefix_length
        && left.address == right.address
        && left.local == right.local
}

fn same_route(left: &RouteRecord, right: &RouteRecord) -> bool {
    left.family == right.family
        && left.destination_prefix_length == right.destination_prefix_length
        && left.source_prefix_length == right.source_prefix_length
        && left.destination == right.destination
        && left.source == right.source
        && left.table == right.table
        && left.route_type == right.route_type
        && left.protocol == right.protocol
        && left.priority == right.priority
}

fn same_rule(left: &RuleRecord, right: &RuleRecord) -> bool {
    if left.family != right.family {
        return false;
    }
    match (left.priority, right.priority) {
        (Some(left), Some(right)) => left == right,
        _ => {
            left.destination_prefix_length == right.destination_prefix_length
                && left.source_prefix_length == right.source_prefix_length
                && left.destination == right.destination
                && left.source == right.source
                && left.table == right.table
                && left.action == right.action
        }
    }
}

fn same_neighbor(left: &NeighborRecord, right: &NeighborRecord) -> bool {
    left.family == right.family
        && left.interface_index == right.interface_index
        && left.destination == right.destination
}

fn normalize_link(
    message: LinkMessage,
    unknown_bytes: &mut usize,
) -> Result<InterfaceRecord, SnapshotError> {
    let mut record = InterfaceRecord {
        index: message.header.index,
        name: String::new(),
        flags: message.header.flags.bits(),
        link_layer_type: message.header.link_layer_type.into(),
        mtu: None,
        hardware_address: Vec::new(),
        permanent_hardware_address: Vec::new(),
        controller_index: None,
        link_index: None,
        link_netns_id: None,
        operational_state: None,
        link_kind: None,
        unknown_attributes: Vec::new(),
    };
    for attribute in message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => {
                validate_string(&value)?;
                record.name = value;
            }
            LinkAttribute::Mtu(value) => record.mtu = Some(value),
            LinkAttribute::Address(value) => {
                validate_link_address(&value)?;
                record.hardware_address = value;
            }
            LinkAttribute::PermAddress(value) => {
                validate_link_address(&value)?;
                record.permanent_hardware_address = value;
            }
            LinkAttribute::Controller(value) => record.controller_index = nonzero(value),
            LinkAttribute::Link(value) => record.link_index = nonzero(value),
            LinkAttribute::LinkNetNsId(value) => record.link_netns_id = Some(value),
            LinkAttribute::OperState(value) => record.operational_state = Some(value.into()),
            LinkAttribute::LinkInfo(values) => {
                for value in values {
                    if let LinkInfo::Kind(kind) = value {
                        let value = kind.to_string();
                        validate_string(&value)?;
                        record.link_kind = Some(value);
                    }
                }
            }
            LinkAttribute::Other(value) => record
                .unknown_attributes
                .push(copy_unknown(&value, unknown_bytes)?),
            _ => {}
        }
    }
    if record.name.is_empty() {
        return Err(SnapshotError::decode(
            "link normalization",
            "missing interface name",
        ));
    }
    Ok(record)
}

fn normalize_address(
    message: AddressMessage,
    unknown_bytes: &mut usize,
) -> Result<AddressRecord, SnapshotError> {
    let family = checked_family(message.header.family.into())?;
    let mut flags = u32::from(message.header.flags.bits());
    let mut record = AddressRecord {
        interface_index: message.header.index,
        family,
        prefix_length: message.header.prefix_len,
        scope: message.header.scope.into(),
        flags,
        address: None,
        local: None,
        label: None,
        broadcast: None,
        unknown_attributes: Vec::new(),
    };
    for attribute in message.attributes {
        match attribute {
            AddressAttribute::Address(value) => record.address = Some(value),
            AddressAttribute::Local(value) => record.local = Some(value),
            AddressAttribute::Label(value) => {
                validate_string(&value)?;
                record.label = Some(value);
            }
            AddressAttribute::Broadcast(value) => record.broadcast = Some(value.into()),
            AddressAttribute::Flags(value) => flags = value.bits(),
            AddressAttribute::Other(value) => record
                .unknown_attributes
                .push(copy_unknown(&value, unknown_bytes)?),
            _ => {}
        }
    }
    record.flags = flags;
    Ok(record)
}

#[allow(
    clippy::too_many_lines,
    reason = "route fields stay adjacent to their project-owned normalized representation"
)]
fn normalize_route(
    message: RouteMessage,
    unknown_bytes: &mut usize,
) -> Result<RouteRecord, SnapshotError> {
    let family = checked_family(message.header.address_family.into())?;
    let mut record = RouteRecord {
        family,
        destination_prefix_length: message.header.destination_prefix_length,
        source_prefix_length: message.header.source_prefix_length,
        destination: None,
        source: None,
        table: u32::from(message.header.table),
        route_type: message.header.kind.into(),
        scope: message.header.scope.into(),
        protocol: message.header.protocol.into(),
        priority: None,
        preferred_source: None,
        gateway: None,
        input_interface: None,
        output_interface: None,
        metrics: Vec::new(),
        multipath: Vec::new(),
        has_encapsulation: false,
        unknown_attributes: Vec::new(),
    };
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Destination(value) => record.destination = route_address(&value)?,
            RouteAttribute::Source(value) => record.source = route_address(&value)?,
            RouteAttribute::Table(value) => record.table = value,
            RouteAttribute::Priority(value) => record.priority = Some(value),
            RouteAttribute::PrefSource(value) => {
                record.preferred_source = route_address(&value)?;
            }
            RouteAttribute::Gateway(value) => record.gateway = route_address(&value)?,
            RouteAttribute::Iif(value) => record.input_interface = nonzero(value),
            RouteAttribute::Oif(value) => record.output_interface = nonzero(value),
            RouteAttribute::Metrics(values) => {
                for value in values {
                    match metric_record(value) {
                        Ok(metric) => record.metrics.push(metric),
                        Err(Some(other)) => record
                            .unknown_attributes
                            .push(copy_unknown(&other, unknown_bytes)?),
                        Err(None) => {
                            return Err(SnapshotError::decode(
                                "route metric normalization",
                                "unrecognized typed metric variant",
                            ));
                        }
                    }
                }
            }
            RouteAttribute::MultiPath(values) => {
                if values.len() > MAX_MULTIPATH_NEXT_HOPS {
                    return Err(SnapshotError::LimitExceeded {
                        resource: SnapshotResource::MultipathNextHops,
                        actual: values.len(),
                        maximum: MAX_MULTIPATH_NEXT_HOPS,
                    });
                }
                for value in values {
                    record
                        .multipath
                        .push(normalize_next_hop(value, unknown_bytes)?);
                }
            }
            RouteAttribute::Via(_)
            | RouteAttribute::NewDestination(_)
            | RouteAttribute::EncapType(_)
            | RouteAttribute::Encap(_) => record.has_encapsulation = true,
            RouteAttribute::Other(value) => record
                .unknown_attributes
                .push(copy_unknown(&value, unknown_bytes)?),
            _ => {}
        }
    }
    record.metrics.sort();
    record.multipath.sort();
    Ok(record)
}

pub(crate) fn normalize_route_message(message: RouteMessage) -> Result<RouteRecord, SnapshotError> {
    normalize_route(message, &mut 0)
}

fn normalize_next_hop(
    value: RouteNextHop,
    unknown_bytes: &mut usize,
) -> Result<RouteNextHopRecord, SnapshotError> {
    let mut record = RouteNextHopRecord {
        interface_index: value.interface_index,
        hops: value.hops,
        flags: value.flags.bits(),
        gateway: None,
        unknown_attributes: Vec::new(),
    };
    for attribute in value.attributes {
        match attribute {
            RouteAttribute::Gateway(value) => record.gateway = route_address(&value)?,
            RouteAttribute::Other(value) => record
                .unknown_attributes
                .push(copy_unknown(&value, unknown_bytes)?),
            _ => {}
        }
    }
    Ok(record)
}

fn normalize_rule(
    message: RuleMessage,
    unknown_bytes: &mut usize,
) -> Result<RuleRecord, SnapshotError> {
    let family = checked_family(message.header.family.into())?;
    let mut record = RuleRecord {
        family,
        destination_prefix_length: message.header.dst_len,
        source_prefix_length: message.header.src_len,
        destination: None,
        source: None,
        table: u32::from(message.header.table),
        action: message.header.action.into(),
        priority: None,
        input_interface: None,
        output_interface: None,
        firewall_mark: None,
        firewall_mask: None,
        uid_range: None,
        ip_protocol: None,
        source_port_range: None,
        destination_port_range: None,
        unknown_attributes: Vec::new(),
    };
    for attribute in message.attributes {
        match attribute {
            RuleAttribute::Destination(value) => record.destination = Some(value),
            RuleAttribute::Source(value) => record.source = Some(value),
            RuleAttribute::Table(value) => record.table = value,
            RuleAttribute::Priority(value) => record.priority = Some(value),
            RuleAttribute::Iifname(value) => {
                validate_string(&value)?;
                record.input_interface = Some(value);
            }
            RuleAttribute::Oifname(value) => {
                validate_string(&value)?;
                record.output_interface = Some(value);
            }
            RuleAttribute::FwMark(value) => record.firewall_mark = Some(value),
            RuleAttribute::FwMask(value) => record.firewall_mask = Some(value),
            RuleAttribute::UidRange(value) => {
                record.uid_range = Some(InclusiveRange {
                    start: value.start,
                    end: value.end,
                });
            }
            RuleAttribute::IpProtocol(value) => record.ip_protocol = Some(value.into()),
            RuleAttribute::SourcePortRange(value) => {
                record.source_port_range = Some(InclusiveRange {
                    start: value.start,
                    end: value.end,
                });
            }
            RuleAttribute::DestinationPortRange(value) => {
                record.destination_port_range = Some(InclusiveRange {
                    start: value.start,
                    end: value.end,
                });
            }
            RuleAttribute::Other(value) => record
                .unknown_attributes
                .push(copy_unknown(&value, unknown_bytes)?),
            _ => {}
        }
    }
    Ok(record)
}

fn normalize_neighbor(
    message: NeighbourMessage,
    unknown_bytes: &mut usize,
) -> Result<NeighborRecord, SnapshotError> {
    let family = checked_family(message.header.family.into())?;
    let mut record = NeighborRecord {
        family,
        interface_index: message.header.ifindex,
        destination: None,
        state: message.header.state.into(),
        flags: message.header.flags.bits(),
        neighbor_type: route_type_u8(message.header.kind),
        link_layer_address: Vec::new(),
        probes: None,
        unknown_attributes: Vec::new(),
    };
    for attribute in message.attributes {
        match attribute {
            NeighbourAttribute::Destination(value) => {
                record.destination = neighbor_address(&value)?;
            }
            NeighbourAttribute::LinkLayerAddress(value) => {
                validate_link_address(&value)?;
                record.link_layer_address = value;
            }
            NeighbourAttribute::Probes(value) => record.probes = Some(value),
            NeighbourAttribute::Other(value) => record
                .unknown_attributes
                .push(copy_unknown(&value, unknown_bytes)?),
            _ => {}
        }
    }
    Ok(record)
}

fn metric_record(metric: RouteMetric) -> Result<RouteMetricRecord, Option<DefaultNla>> {
    let (kind, value) = match metric {
        RouteMetric::Lock(value) => (1, value),
        RouteMetric::Mtu(value) => (2, value),
        RouteMetric::Window(value) => (3, value),
        RouteMetric::Rtt(value) => (4, value),
        RouteMetric::RttVar(value) => (5, value),
        RouteMetric::SsThresh(value) => (6, value),
        RouteMetric::Cwnd(value) => (7, value),
        RouteMetric::Advmss(value) => (8, value),
        RouteMetric::Reordering(value) => (9, value),
        RouteMetric::Hoplimit(value) => (10, value),
        RouteMetric::InitCwnd(value) => (11, value),
        RouteMetric::Features(value) => (12, value),
        RouteMetric::RtoMin(value) => (13, value),
        RouteMetric::InitRwnd(value) => (14, value),
        RouteMetric::QuickAck(value) => (15, value),
        RouteMetric::CcAlgo(value) => (16, value),
        RouteMetric::FastopenNoCookie(value) => (17, value),
        RouteMetric::Other(value) => return Err(Some(value)),
        _ => return Err(None),
    };
    Ok(RouteMetricRecord { kind, value })
}

fn copy_unknown(
    attribute: &impl Nla,
    unknown_bytes: &mut usize,
) -> Result<UnknownAttribute, SnapshotError> {
    let length = attribute.value_len();
    if length > MAX_UNKNOWN_ATTRIBUTE_BYTES {
        return Err(SnapshotError::LimitExceeded {
            resource: SnapshotResource::UnknownAttributeBytes,
            actual: length,
            maximum: MAX_UNKNOWN_ATTRIBUTE_BYTES,
        });
    }
    let total = unknown_bytes
        .checked_add(length)
        .ok_or(SnapshotError::LimitExceeded {
            resource: SnapshotResource::SnapshotUnknownBytes,
            actual: usize::MAX,
            maximum: MAX_SNAPSHOT_UNKNOWN_BYTES,
        })?;
    if total > MAX_SNAPSHOT_UNKNOWN_BYTES {
        return Err(SnapshotError::LimitExceeded {
            resource: SnapshotResource::SnapshotUnknownBytes,
            actual: total,
            maximum: MAX_SNAPSHOT_UNKNOWN_BYTES,
        });
    }
    let mut value = vec![0_u8; length];
    attribute.emit_value(&mut value);
    *unknown_bytes = total;
    Ok(UnknownAttribute {
        kind: attribute.kind(),
        value,
    })
}

fn route_address(value: &RouteAddress) -> Result<Option<IpAddr>, SnapshotError> {
    match value {
        RouteAddress::Inet(value) => Ok(Some((*value).into())),
        RouteAddress::Inet6(value) => Ok(Some((*value).into())),
        RouteAddress::Mpls(_) | RouteAddress::Other(_) => {
            Err(SnapshotError::UnsupportedAddressFamily(0))
        }
        _ => Err(SnapshotError::UnsupportedAddressFamily(0)),
    }
}

fn neighbor_address(value: &NeighbourAddress) -> Result<Option<IpAddr>, SnapshotError> {
    match value {
        NeighbourAddress::Inet(value) => Ok(Some((*value).into())),
        NeighbourAddress::Inet6(value) => Ok(Some((*value).into())),
        _ => Err(SnapshotError::UnsupportedAddressFamily(0)),
    }
}

fn checked_family(family: u8) -> Result<u8, SnapshotError> {
    if matches!(family, 2 | 10) {
        Ok(family)
    } else {
        Err(SnapshotError::UnsupportedAddressFamily(family))
    }
}

fn validate_string(value: &str) -> Result<(), SnapshotError> {
    let length = value.len().saturating_add(1);
    if length > MAX_STRING_ATTRIBUTE_BYTES {
        return Err(SnapshotError::LimitExceeded {
            resource: SnapshotResource::StringBytes,
            actual: length,
            maximum: MAX_STRING_ATTRIBUTE_BYTES,
        });
    }
    Ok(())
}

fn validate_link_address(value: &[u8]) -> Result<(), SnapshotError> {
    if value.len() > MAX_LINK_LAYER_ADDRESS_BYTES {
        return Err(SnapshotError::LimitExceeded {
            resource: SnapshotResource::LinkLayerAddressBytes,
            actual: value.len(),
            maximum: MAX_LINK_LAYER_ADDRESS_BYTES,
        });
    }
    Ok(())
}

fn push_bounded<T>(
    output: &mut Vec<T>,
    value: T,
    maximum: usize,
    resource: SnapshotResource,
) -> Result<(), SnapshotError> {
    if output.len() == maximum {
        return Err(SnapshotError::LimitExceeded {
            resource,
            actual: output.len() + 1,
            maximum,
        });
    }
    output.push(value);
    Ok(())
}

fn validate_reference(index: Option<u32>, interfaces: &BTreeSet<u32>) -> Result<(), SnapshotError> {
    if let Some(index) = index
        && !interfaces.contains(&index)
    {
        return Err(SnapshotError::incomplete(
            IncompleteReason::DisappearingInterface(index),
        ));
    }
    Ok(())
}

const fn nonzero(value: u32) -> Option<u32> {
    if value == 0 { None } else { Some(value) }
}

fn route_type_u8(value: RouteType) -> u8 {
    value.into()
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::DefaultNla;
    use netlink_packet_route::{
        AddressFamily, RouteNetlinkMessage,
        address::AddressMessage,
        link::{LinkAttribute, LinkMessage},
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    };

    use super::NormalizedParts;
    use crate::{
        MAX_LINK_LAYER_ADDRESS_BYTES, MAX_UNKNOWN_ATTRIBUTE_BYTES, SnapshotError, SnapshotResource,
        decoder::BufferedNotification,
    };

    #[test]
    fn preserves_bounded_unknown_attributes() {
        let mut link = LinkMessage::default();
        link.header.index = 7;
        link.attributes = vec![
            LinkAttribute::IfName("test0".into()),
            LinkAttribute::Other(DefaultNla::new(0x123, vec![1, 2, 3])),
        ];
        let mut parts = NormalizedParts::default();
        parts
            .push_messages(vec![RouteNetlinkMessage::NewLink(link)])
            .unwrap();
        let parts = parts.finish().unwrap();
        assert_eq!(parts.interfaces[0].unknown_attributes[0].kind, 0x123);
        assert_eq!(parts.interfaces[0].unknown_attributes[0].value, [1, 2, 3]);
    }

    #[test]
    fn accepts_a_link_peer_that_is_explicitly_in_another_namespace() {
        let mut link = LinkMessage::default();
        link.header.index = 3;
        link.attributes = vec![
            LinkAttribute::IfName("scan0".into()),
            LinkAttribute::Link(2),
            LinkAttribute::LinkNetNsId(0),
        ];
        let mut parts = NormalizedParts::default();
        parts
            .push_messages(vec![RouteNetlinkMessage::NewLink(link)])
            .unwrap();
        let parts = parts.finish().unwrap();
        assert_eq!(parts.interfaces[0].link_index, Some(2));
        assert_eq!(parts.interfaces[0].link_netns_id, Some(0));
    }

    #[test]
    fn rejects_oversized_unknown_attributes_and_dangling_interfaces() {
        let mut link = LinkMessage::default();
        link.header.index = 7;
        link.attributes = vec![
            LinkAttribute::IfName("test0".into()),
            LinkAttribute::Other(DefaultNla::new(
                0x123,
                vec![0; MAX_UNKNOWN_ATTRIBUTE_BYTES + 1],
            )),
        ];
        let mut parts = NormalizedParts::default();
        assert!(matches!(
            parts.push_messages(vec![RouteNetlinkMessage::NewLink(link)]),
            Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::UnknownAttributeBytes,
                ..
            })
        ));

        let mut link = LinkMessage::default();
        link.header.index = 7;
        link.attributes = vec![
            LinkAttribute::IfName("test0".into()),
            LinkAttribute::Address(vec![0; MAX_LINK_LAYER_ADDRESS_BYTES + 1]),
        ];
        let mut parts = NormalizedParts::default();
        assert!(matches!(
            parts.push_messages(vec![RouteNetlinkMessage::NewLink(link)]),
            Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::LinkLayerAddressBytes,
                ..
            })
        ));

        let mut address = AddressMessage::default();
        address.header.family = netlink_packet_route::AddressFamily::Inet;
        address.header.index = 99;
        let mut parts = NormalizedParts::default();
        parts
            .push_messages(vec![RouteNetlinkMessage::NewAddress(address)])
            .unwrap();
        assert!(matches!(
            parts.finish(),
            Err(SnapshotError::Incomplete { .. })
        ));
    }

    #[test]
    fn notifications_replace_and_delete_normalized_records_by_identity() {
        let mut link = LinkMessage::default();
        link.header.index = 7;
        link.attributes = vec![
            LinkAttribute::IfName("test0".into()),
            LinkAttribute::Mtu(1_500),
        ];
        let mut neighbor = neighbor(NeighbourState::Reachable);
        let mut parts = NormalizedParts::default();
        parts
            .push_messages(vec![
                RouteNetlinkMessage::NewLink(link.clone()),
                RouteNetlinkMessage::NewNeighbour(neighbor.clone()),
            ])
            .unwrap();

        link.attributes[1] = LinkAttribute::Mtu(1_280);
        neighbor.header.state = NeighbourState::Failed;
        parts
            .apply_notifications(vec![
                BufferedNotification {
                    message: RouteNetlinkMessage::NewLink(link),
                    bytes: 64,
                },
                BufferedNotification {
                    message: RouteNetlinkMessage::NewNeighbour(neighbor.clone()),
                    bytes: 64,
                },
            ])
            .unwrap();
        assert_eq!(parts.interfaces.len(), 1);
        assert_eq!(parts.interfaces[0].mtu, Some(1_280));
        assert_eq!(parts.neighbors.len(), 1);
        assert_eq!(parts.neighbors[0].state, 0x20);

        parts
            .apply_notifications(vec![BufferedNotification {
                message: RouteNetlinkMessage::DelNeighbour(neighbor),
                bytes: 64,
            }])
            .unwrap();
        assert!(parts.neighbors.is_empty());
        parts.finish().unwrap();
    }

    fn neighbor(state: NeighbourState) -> NeighbourMessage {
        let mut message = NeighbourMessage::default();
        message.header.family = AddressFamily::Inet;
        message.header.ifindex = 7;
        message.header.state = state;
        message.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet("192.0.2.2".parse().unwrap())),
            NeighbourAttribute::LinkLayerAddress(vec![0x02, 0, 0, 0, 0, 2]),
        ];
        message
    }
}
