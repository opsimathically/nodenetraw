use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use nodenet_linux_context::RoutePlanKind;
use nodenet_protocols::{
    ArpEthernetIpv4Operation, ArpEthernetIpv4Packet, CorrelationEvidenceKind, CorrelationToken,
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, EthernetFrame, EthernetHeader,
    EvidenceStrength, Icmpv4Message, Icmpv6Message, Icmpv6Packet, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv6Packet, MacAddress, NdpContext, NdpMessage, NdpOption, NdpPacket,
    ParseMode, ParsedArpPacket, ParsedIcmpv4Message, ParsedIcmpv6Message, ParsedNdpMessage,
    ParsedNdpOption, Port, ProbeIdentity, ResponseTuple, SessionSecret, TcpFlags, TcpSegment,
    TransportChecksumContext, UdpChecksumMode, UdpDatagram, UpperLayerState, VlanStack, VlanTag,
    VlanTagProtocol, classify_echo_reply, classify_quoted_response, classify_tcp_reply,
    classify_udp_reply, compute_transport_checksum, parse_arp_packet, parse_ethernet_frame,
    parse_icmpv4_message, parse_icmpv6_message, parse_ipv4_packet, parse_ipv6_packet,
    parse_ndp_message, parse_tcp_segment, parse_udp_datagram,
};
use nodenetscanner_engine::{
    EmissionPurpose, EvidenceEvent, EvidenceKind, LogicalProbe, ProbeEmission, ProbeFamily,
};

use crate::error::ScannerError;
use crate::model::{SessionOptions, VlanOverride, to_protocol_address};
use crate::socket::{PacketMessage, PortableSockets, RawFamily, RawMessage};

const PACKET_OUTGOING: u8 = 4;

#[derive(Clone, Debug)]
pub(crate) struct RouteBinding {
    pub generation: u64,
    pub kind: RoutePlanKind,
    pub interface_index: u32,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub next_hop: IpAddr,
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
}

#[derive(Clone, Copy, Debug)]
struct ProbeWire {
    probe: LogicalProbe,
    identity: ProbeIdentity,
    token: CorrelationToken,
    route: RouteBindingKey,
    purpose: EmissionPurpose,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RouteBindingKey {
    probe_id: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ObservedEvidence {
    pub event: EvidenceEvent,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WireProgress {
    pub sent: u64,
    pub invalid: u64,
    pub retried: u64,
}

pub(crate) struct WireState {
    secret: SessionSecret,
    session_slot: u8,
    options: SessionOptions,
    routes: HashMap<u64, RouteBinding>,
    probes: HashMap<u64, ProbeWire>,
    learned_neighbors: HashMap<(u32, IpAddr), [u8; 6]>,
    terminal_deadlines: HashMap<u64, Instant>,
    progress: WireProgress,
}

impl WireState {
    pub(crate) fn new(secret: [u8; 32], session_slot: u8, options: SessionOptions) -> Self {
        Self {
            secret: SessionSecret::from_os_random(secret),
            session_slot,
            options,
            routes: HashMap::new(),
            probes: HashMap::new(),
            learned_neighbors: HashMap::new(),
            terminal_deadlines: HashMap::new(),
            progress: WireProgress::default(),
        }
    }

    pub(crate) const fn progress(&self) -> WireProgress {
        self.progress
    }

    pub(crate) fn mark_terminal(&mut self, probe_ids: impl IntoIterator<Item = u64>) {
        let deadline = Instant::now()
            .checked_add(self.options.late_grace)
            .unwrap_or_else(Instant::now);
        for probe_id in probe_ids {
            self.terminal_deadlines.insert(probe_id, deadline);
        }
        self.prune_terminal();
    }

    pub(crate) fn prune_terminal(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .terminal_deadlines
            .iter()
            .filter_map(|(probe_id, deadline)| (now >= *deadline).then_some(*probe_id))
            .collect();
        for probe_id in expired {
            self.terminal_deadlines.remove(&probe_id);
            self.routes.remove(&probe_id);
            self.probes.remove(&probe_id);
        }
    }

    pub(crate) fn insert_route(&mut self, probe_id: u64, mut route: RouteBinding) {
        if route.destination_mac.is_none() {
            route.destination_mac = self
                .learned_neighbors
                .get(&(route.interface_index, route.next_hop))
                .copied();
        }
        self.routes.insert(probe_id, route);
    }

    pub(crate) fn has_route(&self, probe_id: u64) -> bool {
        self.routes.contains_key(&probe_id)
    }

    pub(crate) fn generation(&self, probe_id: u64) -> Option<u64> {
        self.routes.get(&probe_id).map(|route| route.generation)
    }

    pub(crate) fn emit(
        &mut self,
        sockets: &PortableSockets,
        emission: ProbeEmission,
    ) -> Result<(), ScannerError> {
        let route = self
            .routes
            .get(&emission.probe_id)
            .cloned()
            .ok_or_else(|| ScannerError::internal("emit probe", "route binding is missing"))?;
        let identity = self.identity(emission.probe_id, emission.probe, &route)?;
        let token = self.secret.derive(identity);
        let packet = match emission.purpose {
            EmissionPurpose::NeighborSetup(family) => Self::build_discovery(family, &route)?,
            EmissionPurpose::Probe => self.build_probe(emission.probe, &route, token)?,
            EmissionPurpose::TcpResetCleanup => {
                return Ok(());
            }
        };
        match route.kind {
            RoutePlanKind::Local | RoutePlanKind::Loopback => {
                sockets.send_raw(route.destination, &packet)?;
            }
            RoutePlanKind::EthernetOnLink
            | RoutePlanKind::EthernetGateway
            | RoutePlanKind::Multicast => {
                let destination_mac =
                    packet_destination_mac(emission.probe, emission.purpose, &route)?;
                let ether_type = match route.destination {
                    IpAddr::V4(_)
                        if matches!(
                            emission.purpose,
                            EmissionPurpose::NeighborSetup(ProbeFamily::Arp)
                        ) || emission.probe.family == ProbeFamily::Arp =>
                    {
                        ETHER_TYPE_ARP
                    }
                    IpAddr::V4(_) => ETHER_TYPE_IPV4,
                    IpAddr::V6(_) => ETHER_TYPE_IPV6,
                };
                let source_mac = route.source_mac.ok_or_else(|| {
                    ScannerError::unsupported(
                        "emit Ethernet probe",
                        "interface has no six-byte hardware address",
                    )
                })?;
                let frame = EthernetFrame {
                    header: EthernetHeader {
                        destination: MacAddress::new(destination_mac),
                        source: MacAddress::new(source_mac),
                        vlan: vlan_stack(self.options.vlan.as_ref())?,
                        ether_type,
                    },
                    payload: &packet,
                }
                .build()?;
                sockets.send_packet(route.interface_index, destination_mac, &frame)?;
            }
        }
        self.progress.sent = self.progress.sent.saturating_add(1);
        if emission.transmission > 1 {
            self.progress.retried = self.progress.retried.saturating_add(1);
        }
        self.probes.insert(
            emission.probe_id,
            ProbeWire {
                probe: emission.probe,
                identity,
                token,
                route: RouteBindingKey {
                    probe_id: emission.probe_id,
                },
                purpose: emission.purpose,
            },
        );
        Ok(())
    }

    pub(crate) fn process_packet(&mut self, message: &PacketMessage) -> Vec<ObservedEvidence> {
        if message.packet_type == PACKET_OUTGOING {
            return Vec::new();
        }
        let Ok(frame) = parse_ethernet_frame(&message.data) else {
            self.progress.invalid = self.progress.invalid.saturating_add(1);
            return Vec::new();
        };
        match frame.header.ether_type {
            value if value == ETHER_TYPE_ARP => {
                self.process_arp(message.interface_index, frame.payload)
            }
            value if value == ETHER_TYPE_IPV4 || value == ETHER_TYPE_IPV6 => {
                self.process_ip(frame.payload, message.checksum_not_ready)
            }
            _ => Vec::new(),
        }
    }

    pub(crate) fn process_raw(&mut self, message: &RawMessage) -> Vec<ObservedEvidence> {
        match message.family {
            RawFamily::Ipv4 => self.process_ip(&message.data, false),
            RawFamily::Ipv6 => {
                let candidates: Vec<(u64, RouteBinding)> = self
                    .probes
                    .iter()
                    .filter_map(|(id, probe)| {
                        let route = self.routes.get(&probe.route.probe_id)?;
                        (route.destination == message.source && route.destination.is_ipv6())
                            .then_some((*id, route.clone()))
                    })
                    .collect();
                let mut output = Vec::new();
                for (probe_id, route) in candidates {
                    output.extend(self.process_transport(
                        to_protocol_address(message.source),
                        to_protocol_address(route.source),
                        message.protocol.number(message.family),
                        &message.data,
                        u8::MAX,
                        Some(probe_id),
                        false,
                    ));
                }
                output
            }
        }
    }

    fn process_ip(&mut self, packet: &[u8], checksum_not_ready: bool) -> Vec<ObservedEvidence> {
        let version = packet.first().map(|value| value >> 4);
        match version {
            Some(4) => {
                let Ok(parsed) = parse_ipv4_packet(packet, ParseMode::Strict) else {
                    self.progress.invalid = self.progress.invalid.saturating_add(1);
                    return Vec::new();
                };
                let UpperLayerState::Reachable {
                    protocol, payload, ..
                } = parsed.upper_layer
                else {
                    return Vec::new();
                };
                self.process_transport(
                    IpAddress::V4(parsed.source),
                    IpAddress::V4(parsed.destination),
                    protocol.get(),
                    payload,
                    parsed.time_to_live,
                    None,
                    checksum_not_ready,
                )
            }
            Some(6) => {
                let Ok(parsed) = parse_ipv6_packet(packet, ParseMode::Strict) else {
                    self.progress.invalid = self.progress.invalid.saturating_add(1);
                    return Vec::new();
                };
                let UpperLayerState::Reachable {
                    protocol, payload, ..
                } = parsed.upper_layer
                else {
                    return Vec::new();
                };
                self.process_transport(
                    IpAddress::V6(parsed.source),
                    IpAddress::V6(parsed.destination),
                    protocol.get(),
                    payload,
                    parsed.hop_limit,
                    None,
                    checksum_not_ready,
                )
            }
            _ => {
                self.progress.invalid = self.progress.invalid.saturating_add(1);
                Vec::new()
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "wire-order dispatch keeps receive metadata, checksum, quote, and correlation checks adjacent"
    )]
    fn process_transport(
        &mut self,
        source: IpAddress,
        destination: IpAddress,
        protocol: u8,
        payload: &[u8],
        hop_limit: u8,
        only_probe: Option<u64>,
        checksum_not_ready: bool,
    ) -> Vec<ObservedEvidence> {
        let checksum_context = checksum_context(source, destination);
        let normalized_payload =
            complete_offloaded_checksum(payload, checksum_context, protocol, checksum_not_ready);
        let payload = normalized_payload.as_deref().unwrap_or(payload);
        let candidates: Vec<(u64, ProbeWire)> = self
            .probes
            .iter()
            .filter(|(id, _)| only_probe.is_none_or(|expected| **id == expected))
            .map(|(id, value)| (*id, *value))
            .collect();
        let mut output = Vec::new();
        match protocol {
            6 => {
                let Ok(segment) = parse_tcp_segment(payload, checksum_context) else {
                    self.progress.invalid = self.progress.invalid.saturating_add(1);
                    return output;
                };
                let tuple = ResponseTuple {
                    source,
                    destination,
                    source_port: segment.source_port,
                    destination_port: segment.destination_port,
                };
                for (probe_id, probe) in candidates {
                    if let Ok(evidence) =
                        classify_tcp_reply(probe.identity, probe.token, tuple, segment)
                    {
                        output.push(observed(probe_id, evidence.kind, evidence.strength, None));
                        break;
                    }
                }
            }
            17 => {
                let Ok(datagram) = parse_udp_datagram(payload, checksum_context) else {
                    self.progress.invalid = self.progress.invalid.saturating_add(1);
                    return output;
                };
                let tuple = ResponseTuple {
                    source,
                    destination,
                    source_port: datagram.source_port,
                    destination_port: datagram.destination_port,
                };
                for (probe_id, probe) in candidates {
                    if let Ok(evidence) = classify_udp_reply(probe.identity, tuple) {
                        output.push(observed(probe_id, evidence.kind, evidence.strength, None));
                        break;
                    }
                }
            }
            1 => {
                let Ok(packet) = parse_icmpv4_message(payload) else {
                    self.progress.invalid = self.progress.invalid.saturating_add(1);
                    return output;
                };
                for (probe_id, probe) in candidates {
                    match packet.message {
                        ParsedIcmpv4Message::EchoReply {
                            identifier,
                            sequence,
                            payload,
                        } => {
                            if let Ok(evidence) = classify_echo_reply(
                                probe.identity,
                                source,
                                destination,
                                identifier,
                                sequence,
                                payload,
                                probe.token,
                            ) {
                                output.push(observed(
                                    probe_id,
                                    evidence.kind,
                                    evidence.strength,
                                    None,
                                ));
                                break;
                            }
                        }
                        ParsedIcmpv4Message::DestinationUnreachable {
                            code,
                            ref quoted_packet,
                            ..
                        } => {
                            if let Ok(quote) = quoted_packet
                                && let Ok(evidence) =
                                    classify_quoted_response(probe.identity, *quote, probe.token)
                            {
                                output.push(observed(
                                    probe_id,
                                    evidence.kind,
                                    evidence.strength,
                                    Some(code),
                                ));
                                break;
                            }
                        }
                        ParsedIcmpv4Message::TimeExceeded {
                            ref quoted_packet, ..
                        }
                        | ParsedIcmpv4Message::ParameterProblem {
                            ref quoted_packet, ..
                        } => {
                            if let Ok(quote) = quoted_packet
                                && let Ok(evidence) =
                                    classify_quoted_response(probe.identity, *quote, probe.token)
                            {
                                output.push(observed(
                                    probe_id,
                                    evidence.kind,
                                    evidence.strength,
                                    Some(255),
                                ));
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            58 => {
                if payload
                    .first()
                    .is_some_and(|kind| matches!(kind, 133..=137))
                {
                    return self.process_ndp(source, destination, hop_limit, payload);
                }
                let Ok(packet) = parse_icmpv6_message(payload, checksum_context) else {
                    self.progress.invalid = self.progress.invalid.saturating_add(1);
                    return output;
                };
                for (probe_id, probe) in candidates {
                    match packet.message {
                        ParsedIcmpv6Message::EchoReply {
                            identifier,
                            sequence,
                            payload,
                        } => {
                            if let Ok(evidence) = classify_echo_reply(
                                probe.identity,
                                source,
                                destination,
                                identifier,
                                sequence,
                                payload,
                                probe.token,
                            ) {
                                output.push(observed(
                                    probe_id,
                                    evidence.kind,
                                    evidence.strength,
                                    None,
                                ));
                                break;
                            }
                        }
                        ParsedIcmpv6Message::DestinationUnreachable {
                            code,
                            ref quoted_packet,
                            ..
                        } => {
                            if let Ok(quote) = quoted_packet
                                && let Ok(evidence) =
                                    classify_quoted_response(probe.identity, *quote, probe.token)
                            {
                                output.push(observed(
                                    probe_id,
                                    evidence.kind,
                                    evidence.strength,
                                    Some(code),
                                ));
                                break;
                            }
                        }
                        ParsedIcmpv6Message::PacketTooBig {
                            ref quoted_packet, ..
                        }
                        | ParsedIcmpv6Message::TimeExceeded {
                            ref quoted_packet, ..
                        }
                        | ParsedIcmpv6Message::ParameterProblem {
                            ref quoted_packet, ..
                        } => {
                            if let Ok(quote) = quoted_packet
                                && let Ok(evidence) =
                                    classify_quoted_response(probe.identity, *quote, probe.token)
                            {
                                output.push(observed(
                                    probe_id,
                                    evidence.kind,
                                    evidence.strength,
                                    Some(255),
                                ));
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        output
    }

    fn process_arp(&mut self, interface_index: u32, payload: &[u8]) -> Vec<ObservedEvidence> {
        let Ok(ParsedArpPacket::EthernetIpv4(packet)) = parse_arp_packet(payload) else {
            self.progress.invalid = self.progress.invalid.saturating_add(1);
            return Vec::new();
        };
        if packet.operation != ArpEthernetIpv4Operation::Reply {
            return Vec::new();
        }
        let sender = IpAddr::V4(packet.sender_protocol_address.into());
        let mac = packet.sender_hardware_address.octets();
        self.learn_neighbor(interface_index, sender, mac);
        self.probes
            .iter()
            .filter_map(|(probe_id, probe)| {
                let route = self.routes.get(&probe.route.probe_id)?;
                (route.interface_index == interface_index
                    && route.next_hop == sender
                    && (probe.probe.family == ProbeFamily::Arp
                        || matches!(
                            probe.purpose,
                            EmissionPurpose::NeighborSetup(ProbeFamily::Arp)
                        )))
                .then(|| {
                    observed(
                        *probe_id,
                        CorrelationEvidenceKind::ArpReply,
                        EvidenceStrength::TupleCorrelatedUnauthenticated,
                        None,
                    )
                })
            })
            .collect()
    }

    fn process_ndp(
        &mut self,
        source: IpAddress,
        destination: IpAddress,
        hop_limit: u8,
        payload: &[u8],
    ) -> Vec<ObservedEvidence> {
        let (IpAddress::V6(source_v6), IpAddress::V6(destination_v6)) = (source, destination)
        else {
            return Vec::new();
        };
        let Ok(packet) = parse_ndp_message(
            payload,
            NdpContext {
                source: source_v6,
                destination: destination_v6,
                hop_limit,
            },
        ) else {
            self.progress.invalid = self.progress.invalid.saturating_add(1);
            return Vec::new();
        };
        let ParsedNdpMessage::NeighborAdvertisement { target, .. } = packet.message else {
            return Vec::new();
        };
        let mac = packet.options.iter().find_map(|option| match option {
            ParsedNdpOption::TargetLinkLayerAddress(value) if value.len() == 6 => {
                value.try_into().ok()
            }
            _ => None,
        });
        let target = IpAddr::V6(target.into());
        let Some(mac) = mac else {
            return Vec::new();
        };
        let interfaces: Vec<u32> = self
            .routes
            .values()
            .filter(|route| route.next_hop == target)
            .map(|route| route.interface_index)
            .collect();
        for interface in interfaces {
            self.learn_neighbor(interface, target, mac);
        }
        self.probes
            .iter()
            .filter_map(|(probe_id, probe)| {
                let route = self.routes.get(&probe.route.probe_id)?;
                (route.next_hop == target
                    && (probe.probe.family == ProbeFamily::Ndp
                        || matches!(
                            probe.purpose,
                            EmissionPurpose::NeighborSetup(ProbeFamily::Ndp)
                        )))
                .then(|| {
                    observed(
                        *probe_id,
                        CorrelationEvidenceKind::NeighborAdvertisement,
                        EvidenceStrength::TupleCorrelatedUnauthenticated,
                        None,
                    )
                })
            })
            .collect()
    }

    fn learn_neighbor(&mut self, interface_index: u32, target: IpAddr, mac: [u8; 6]) {
        self.learned_neighbors
            .insert((interface_index, target), mac);
        for route in self.routes.values_mut() {
            if route.interface_index == interface_index && route.next_hop == target {
                route.destination_mac = Some(mac);
            }
        }
    }

    fn identity(
        &self,
        probe_id: u64,
        probe: LogicalProbe,
        route: &RouteBinding,
    ) -> Result<ProbeIdentity, ScannerError> {
        let protocol = match probe.family {
            ProbeFamily::Arp => 0,
            ProbeFamily::Ndp | ProbeFamily::Icmpv6Echo => 58,
            ProbeFamily::Icmpv4Echo => 1,
            ProbeFamily::TcpSyn => 6,
            ProbeFamily::Udp => 17,
        };
        let source_port = if probe.family.uses_ports() {
            self.source_port(probe_id)
        } else {
            0
        };
        let destination_port = probe.port.map_or(0, nodenet_protocols::ProbePort::get);
        let mixed = probe_id ^ (u64::from(self.session_slot) << 56);
        ProbeIdentity::new(
            IpProtocol::new(protocol),
            probe.attempt,
            to_protocol_address(route.source),
            to_protocol_address(route.destination),
            Port::new(source_port),
            Port::new(destination_port),
            u16::try_from(mixed >> 16).unwrap_or_default(),
            u16::try_from(mixed & 0xffff).unwrap_or_default(),
            probe_id,
        )
        .map_err(|error| ScannerError::invalid("create correlation identity", error.to_string()))
    }

    fn source_port(&self, probe_id: u64) -> u16 {
        let span = u64::from(self.options.source_port_end - self.options.source_port_start) + 1;
        let slot = u64::from(self.session_slot);
        let offset = (probe_id.saturating_mul(4).saturating_add(slot)) % span;
        self.options.source_port_start + u16::try_from(offset).unwrap_or_default()
    }

    fn build_discovery(family: ProbeFamily, route: &RouteBinding) -> Result<Vec<u8>, ScannerError> {
        match (family, route.source, route.next_hop) {
            (ProbeFamily::Arp, IpAddr::V4(source), IpAddr::V4(target)) => {
                let source_mac = route.source_mac.ok_or_else(|| {
                    ScannerError::unsupported("build ARP", "interface has no Ethernet address")
                })?;
                Ok(ArpEthernetIpv4Packet {
                    operation: ArpEthernetIpv4Operation::Request,
                    sender_hardware_address: MacAddress::new(source_mac),
                    sender_protocol_address: Ipv4Address::from(source),
                    target_hardware_address: MacAddress::new([0; 6]),
                    target_protocol_address: Ipv4Address::from(target),
                }
                .build())
            }
            (ProbeFamily::Ndp, IpAddr::V6(source), IpAddr::V6(target)) => {
                build_neighbor_solicitation(source, target, route.source_mac)
            }
            _ => Err(ScannerError::unsupported(
                "build neighbor discovery",
                "address family does not match discovery protocol",
            )),
        }
    }

    fn build_probe(
        &self,
        probe: LogicalProbe,
        route: &RouteBinding,
        token: CorrelationToken,
    ) -> Result<Vec<u8>, ScannerError> {
        if matches!(probe.family, ProbeFamily::Arp | ProbeFamily::Ndp) {
            return Self::build_discovery(probe.family, route);
        }
        let identity = self.identity(probe.logical_id, probe, route)?;
        let payload_token = token.payload_token();
        let transport = match probe.family {
            ProbeFamily::Icmpv4Echo => Icmpv4Message::EchoRequest {
                identifier: u16::try_from(
                    (probe.logical_id ^ (u64::from(self.session_slot) << 56)) >> 16,
                )
                .unwrap_or_default(),
                sequence: u16::try_from(probe.logical_id & 0xffff).unwrap_or_default(),
                payload: &payload_token,
            }
            .build()?,
            ProbeFamily::Icmpv6Echo => Icmpv6Packet {
                checksum_context: transport_context(route.source, route.destination)?,
                message: Icmpv6Message::EchoRequest {
                    identifier: u16::try_from(
                        (probe.logical_id ^ (u64::from(self.session_slot) << 56)) >> 16,
                    )
                    .unwrap_or_default(),
                    sequence: u16::try_from(probe.logical_id & 0xffff).unwrap_or_default(),
                    payload: &payload_token,
                },
            }
            .build()?,
            ProbeFamily::TcpSyn => TcpSegment {
                checksum_context: transport_context(route.source, route.destination)?,
                source_port: Port::new(self.source_port(probe.logical_id)),
                destination_port: Port::new(
                    probe
                        .port
                        .ok_or_else(|| {
                            ScannerError::internal("build TCP SYN", "destination port missing")
                        })?
                        .get(),
                ),
                sequence_number: token.tcp_sequence(),
                acknowledgment_number: 0,
                flags: TcpFlags::SYN,
                window_size: 64_240,
                urgent_pointer: 0,
                options: &[],
                payload: &[],
            }
            .build()?,
            ProbeFamily::Udp => {
                let user = match route.destination {
                    IpAddr::V4(_) => &self.options.udp_payload_v4,
                    IpAddr::V6(_) => &self.options.udp_payload_v6,
                };
                let mut payload = Vec::with_capacity(16 + user.len());
                payload.extend_from_slice(&payload_token);
                payload.extend_from_slice(user);
                UdpDatagram {
                    checksum_context: transport_context(route.source, route.destination)?,
                    checksum_mode: UdpChecksumMode::Compute,
                    source_port: Port::new(self.source_port(probe.logical_id)),
                    destination_port: Port::new(
                        probe
                            .port
                            .ok_or_else(|| {
                                ScannerError::internal("build UDP", "destination port missing")
                            })?
                            .get(),
                    ),
                    payload: &payload,
                }
                .build()?
            }
            ProbeFamily::Arp | ProbeFamily::Ndp => unreachable!("discovery handled above"),
        };
        let protocol = identity.protocol();
        build_ip_packet(
            route.source,
            route.destination,
            protocol,
            probe.logical_id,
            &transport,
        )
    }
}

fn complete_offloaded_checksum(
    payload: &[u8],
    context: TransportChecksumContext,
    protocol: u8,
    checksum_not_ready: bool,
) -> Option<Vec<u8>> {
    let offset = match (checksum_not_ready, protocol) {
        (true, 6) if payload.len() >= 18 => 16,
        (true, 17) if payload.len() >= 8 => 6,
        _ => return None,
    };
    let mut completed = payload.to_vec();
    completed[offset..offset + 2].fill(0);
    let mut checksum = compute_transport_checksum(context, IpProtocol::new(protocol), &completed)?;
    if protocol == 17 && checksum == 0 {
        checksum = u16::MAX;
    }
    completed[offset..offset + 2].copy_from_slice(&checksum.to_be_bytes());
    Some(completed)
}

fn build_ip_packet(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpProtocol,
    probe_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>, ScannerError> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => Ok(Ipv4Packet {
            dscp: 0,
            ecn: 0,
            identification: u16::try_from(probe_id & 0xffff).unwrap_or_default(),
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            time_to_live: 64,
            protocol,
            source: source.into(),
            destination: destination.into(),
            options: &[],
            payload,
        }
        .build()?),
        (IpAddr::V6(source), IpAddr::V6(destination)) => Ok(Ipv6Packet {
            traffic_class: 0,
            flow_label: u32::try_from(probe_id & 0x000f_ffff).unwrap_or_default(),
            hop_limit: 64,
            source: source.into(),
            destination: destination.into(),
            extensions: &[],
            upper_layer_protocol: protocol,
            payload,
        }
        .build()?),
        _ => Err(ScannerError::invalid(
            "build IP packet",
            "source and destination families differ",
        )),
    }
}

fn build_neighbor_solicitation(
    source: Ipv6Addr,
    target: Ipv6Addr,
    source_mac: Option<[u8; 6]>,
) -> Result<Vec<u8>, ScannerError> {
    let target_octets = target.octets();
    let mut destination = [0_u8; 16];
    destination[0] = 0xff;
    destination[1] = 0x02;
    destination[11] = 0x01;
    destination[12] = 0xff;
    destination[13..16].copy_from_slice(&target_octets[13..16]);
    let destination = Ipv6Addr::from(destination);
    let option = source_mac.map(NdpOption::SourceLinkLayerAddress);
    let options = option.as_slice();
    let ndp = NdpPacket {
        context: NdpContext {
            source: source.into(),
            destination: destination.into(),
            hop_limit: u8::MAX,
        },
        message: NdpMessage::NeighborSolicitation {
            target: target.into(),
        },
        options,
    }
    .build()?;
    Ok(Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        hop_limit: u8::MAX,
        source: source.into(),
        destination: destination.into(),
        extensions: &[],
        upper_layer_protocol: IpProtocol::new(58),
        payload: &ndp,
    }
    .build()?)
}

fn transport_context(
    source: IpAddr,
    destination: IpAddr,
) -> Result<TransportChecksumContext, ScannerError> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => Ok(TransportChecksumContext::Ipv4 {
            source: source.into(),
            destination: destination.into(),
        }),
        (IpAddr::V6(source), IpAddr::V6(destination)) => Ok(TransportChecksumContext::Ipv6 {
            source: source.into(),
            destination: destination.into(),
        }),
        _ => Err(ScannerError::invalid(
            "build transport",
            "source and destination families differ",
        )),
    }
}

fn checksum_context(source: IpAddress, destination: IpAddress) -> TransportChecksumContext {
    match (source, destination) {
        (IpAddress::V4(source), IpAddress::V4(destination)) => TransportChecksumContext::Ipv4 {
            source,
            destination,
        },
        (IpAddress::V6(source), IpAddress::V6(destination)) => TransportChecksumContext::Ipv6 {
            source,
            destination,
        },
        _ => unreachable!("parsed packet addresses always share a family"),
    }
}

fn vlan_stack(value: Option<&VlanOverride>) -> Result<VlanStack, ScannerError> {
    value.map_or(Ok(VlanStack::None), |value| {
        Ok(VlanStack::One(VlanTag::new(
            VlanTagProtocol::Dot1Q,
            value.priority,
            value.drop_eligible,
            value.identifier,
        )?))
    })
}

fn packet_destination_mac(
    probe: LogicalProbe,
    purpose: EmissionPurpose,
    route: &RouteBinding,
) -> Result<[u8; 6], ScannerError> {
    if matches!(purpose, EmissionPurpose::NeighborSetup(ProbeFamily::Arp))
        || probe.family == ProbeFamily::Arp
    {
        return Ok([0xff; 6]);
    }
    if matches!(purpose, EmissionPurpose::NeighborSetup(ProbeFamily::Ndp))
        || probe.family == ProbeFamily::Ndp
    {
        let IpAddr::V6(target) = route.next_hop else {
            return Err(ScannerError::invalid("build NDP", "NDP requires IPv6"));
        };
        let octets = target.octets();
        return Ok([0x33, 0x33, 0xff, octets[13], octets[14], octets[15]]);
    }
    route.destination_mac.ok_or_else(|| {
        ScannerError::unsupported("emit Ethernet probe", "next-hop link address is unresolved")
    })
}

fn observed(
    probe_id: u64,
    kind: CorrelationEvidenceKind,
    strength: EvidenceStrength,
    icmp_code: Option<u8>,
) -> ObservedEvidence {
    let kind = match kind {
        CorrelationEvidenceKind::TcpSynAcknowledgment => EvidenceKind::TcpSynAcknowledgment,
        CorrelationEvidenceKind::TcpReset => EvidenceKind::TcpReset,
        CorrelationEvidenceKind::EchoReply => EvidenceKind::EchoReply,
        CorrelationEvidenceKind::UdpReply => EvidenceKind::UdpReply,
        CorrelationEvidenceKind::ArpReply => EvidenceKind::ArpReply,
        CorrelationEvidenceKind::NeighborAdvertisement => EvidenceKind::NeighborAdvertisement,
        CorrelationEvidenceKind::IcmpErrorQuote => match icmp_code {
            Some(3 | 4) => EvidenceKind::IcmpPortUnreachable,
            Some(0 | 1 | 2 | 5 | 6 | 7 | 9 | 10 | 13) => EvidenceKind::ExplicitUnreachable,
            _ => EvidenceKind::IcmpOtherError,
        },
    };
    ObservedEvidence {
        event: EvidenceEvent {
            probe_id,
            kind,
            strength,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solicited_node_packet_is_checksum_valid_and_strictly_parseable() {
        let packet = build_neighbor_solicitation(
            "fe80::1".parse().unwrap(),
            "fe80::abcd".parse().unwrap(),
            Some([0, 1, 2, 3, 4, 5]),
        )
        .unwrap();
        let parsed = parse_ipv6_packet(&packet, ParseMode::Strict).unwrap();
        assert_eq!(parsed.hop_limit, u8::MAX);
    }

    #[test]
    fn vlan_override_builds_one_checked_dot1q_tag() {
        let stack = vlan_stack(Some(&VlanOverride {
            identifier: 7,
            priority: 3,
            drop_eligible: true,
        }))
        .unwrap();
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn explicit_offload_status_completes_a_private_transport_copy() {
        let context = TransportChecksumContext::Ipv4 {
            source: "192.0.2.2".parse::<std::net::Ipv4Addr>().unwrap().into(),
            destination: "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap().into(),
        };
        let mut segment = TcpSegment {
            checksum_context: context,
            source_port: Port::new(443),
            destination_port: Port::new(49_152),
            sequence_number: 1,
            acknowledgment_number: 2,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            window_size: 1,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        }
        .build()
        .unwrap();
        segment[16..18].copy_from_slice(&1_u16.to_be_bytes());
        assert!(parse_tcp_segment(&segment, context).is_err());
        let completed = complete_offloaded_checksum(&segment, context, 6, true).unwrap();
        assert!(parse_tcp_segment(&completed, context).is_ok());
        assert_eq!(segment[16..18], 1_u16.to_be_bytes());
    }
}
