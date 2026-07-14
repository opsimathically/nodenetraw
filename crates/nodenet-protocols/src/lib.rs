//! Bounded, syscall-free protocol foundations shared by the `nodenet` crates.
//!
//! This crate deliberately owns its public types and errors. Codec dependencies
//! are implementation details and may be replaced without changing consumers.

mod arp;
mod bounds;
mod checksum;
mod correlation;
mod envelope;
mod error;
mod icmpv4;
mod icmpv6;
mod ipv4;
mod ipv6;
mod link;
mod ndp;
mod network;
mod parse;
mod quoted;
mod tcp;
mod template;
mod types;
mod udp;
mod writer;

pub use arp::{
    ArpEthernetIpv4Operation, ArpEthernetIpv4Packet, ParsedArpPacket, UnknownArpPacket,
    parse_arp_packet,
};
pub use bounds::{
    MAX_CORRELATION_LEASES, MAX_ETHERNET_FRAME_LENGTH, MAX_ICMPV4_MESSAGE_BYTES,
    MAX_ICMPV6_MESSAGE_BYTES, MAX_IP_PACKET_LENGTH, MAX_IPV6_EXTENSION_BYTES,
    MAX_IPV6_EXTENSION_HEADER_COUNT, MAX_NDP_OPTION_BYTES, MAX_NDP_OPTION_COUNT,
    MAX_OWNED_OPTION_BYTES, MAX_OWNED_PAYLOAD_BYTES, MAX_TCP_OPTION_BYTES, MAX_TCP_OPTION_COUNT,
    MAX_TEMPLATE_PATCH_DESCRIPTORS, MAX_VLAN_HEADER_COUNT, PacketKind, PacketLength,
};
pub use checksum::{
    TransportChecksumContext, compute_internet_checksum, compute_transport_checksum,
    validate_internet_checksum, validate_transport_checksum,
};
pub use correlation::{
    CorrelationEvidence, CorrelationEvidenceKind, CorrelationIdentityError, CorrelationLeaseKey,
    CorrelationRejection, CorrelationReuseGuard, CorrelationToken, EvidenceStrength, ProbeIdentity,
    ResponseTuple, ReuseGuardError, SessionSecret, classify_arp_reply, classify_echo_reply,
    classify_neighbor_advertisement, classify_quoted_response, classify_tcp_reply,
    classify_udp_reply,
};
pub use envelope::{ParsedNetworkFrame, ParsedNetworkPayload, parse_network_frame};
pub use error::{BuildError, Field, Layer, ParseError, Resource};
pub use icmpv4::{
    Icmpv4Conformance, Icmpv4Message, ParsedIcmpv4Message, ParsedIcmpv4Packet, parse_icmpv4_message,
};
pub use icmpv6::{
    Icmpv6Conformance, Icmpv6Message, Icmpv6Packet, ParsedIcmpv6Message, ParsedIcmpv6Packet,
    parse_icmpv6_message,
};
pub use ipv4::{Ipv4Conformance, Ipv4Packet, ParsedIpv4Packet, parse_ipv4_packet};
pub use ipv6::{
    Ipv6Conformance, Ipv6Extension, Ipv6Packet, ParsedIpv6Extension, ParsedIpv6Extensions,
    ParsedIpv6Packet, parse_ipv6_packet,
};
pub use link::{
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, ETHER_TYPE_PROVIDER_BRIDGING,
    ETHER_TYPE_VLAN, EthernetFrame, EthernetHeader, ParsedEthernetFrame, VlanStack, VlanTag,
    VlanTagProtocol, parse_ethernet_frame,
};
pub use ndp::{
    NdpConformance, NdpContext, NdpMessage, NdpOption, NdpPacket, ParsedNdpMessage,
    ParsedNdpOption, ParsedNdpOptions, ParsedNdpPacket, parse_ndp_message,
};
pub use network::{FragmentState, UpperLayerState};
pub use parse::{PacketStart, ParseStatus, inspect_packet};
pub use quoted::{QuotedIpPacket, QuotedTransport, parse_quoted_ip_packet};
pub use tcp::{
    ParsedTcpOption, ParsedTcpOptions, ParsedTcpSackBlocks, ParsedTcpSegment, TcpConformance,
    TcpFlags, TcpOption, TcpSackBlock, TcpSegment, parse_tcp_segment,
};
pub use template::{FrameTemplate, PatchDescriptor, PatchKind, PatchValue, TemplatePatch};
pub use types::{
    EtherType, InternetChecksum, IpAddress, IpProtocol, Ipv4Address, Ipv6Address, MacAddress,
    OwnedOptions, OwnedPayload, PacketSpan, ParseMode, Port, ProbePort,
};
pub use udp::{
    OwnedUdpDatagram, ParsedUdpDatagram, UdpChecksumMode, UdpChecksumStatus, UdpDatagram,
    parse_udp_datagram,
};
pub use writer::{OwnedPacket, PacketPlan};

#[cfg(feature = "fuzzing")]
pub mod fuzzing;
