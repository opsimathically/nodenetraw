use crate::{
    ETHER_TYPE_ARP, ETHER_TYPE_IPV4, ETHER_TYPE_IPV6, EtherType, ParseError, ParseMode,
    ParsedArpPacket, ParsedEthernetFrame, ParsedIpv4Packet, ParsedIpv6Packet, parse_arp_packet,
    parse_ethernet_frame, parse_ipv4_packet, parse_ipv6_packet,
};

/// The safely identified network payload inside an Ethernet frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "borrowed parse results remain allocation-free under hostile input"
)]
pub enum ParsedNetworkPayload<'a> {
    Arp(ParsedArpPacket<'a>),
    Ipv4(ParsedIpv4Packet<'a>),
    Ipv6(ParsedIpv6Packet<'a>),
    Opaque {
        ether_type: EtherType,
        payload: &'a [u8],
    },
}

/// A validated Ethernet envelope and its explicit network-layer disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedNetworkFrame<'a> {
    pub ethernet: ParsedEthernetFrame<'a>,
    pub network: ParsedNetworkPayload<'a>,
}

/// Parses an Ethernet envelope and dispatches only recognized L3 `EtherType` values.
///
/// # Errors
///
/// Returns the structured Ethernet or recognized network-layer parse error.
pub fn parse_network_frame(
    input: &[u8],
    mode: ParseMode,
) -> Result<ParsedNetworkFrame<'_>, ParseError> {
    let ethernet = parse_ethernet_frame(input)?;
    let network = match ethernet.header.ether_type {
        ETHER_TYPE_ARP => ParsedNetworkPayload::Arp(parse_arp_packet(ethernet.payload)?),
        ETHER_TYPE_IPV4 => ParsedNetworkPayload::Ipv4(parse_ipv4_packet(ethernet.payload, mode)?),
        ETHER_TYPE_IPV6 => ParsedNetworkPayload::Ipv6(parse_ipv6_packet(ethernet.payload, mode)?),
        ether_type => ParsedNetworkPayload::Opaque {
            ether_type,
            payload: ethernet.payload,
        },
    };
    Ok(ParsedNetworkFrame { ethernet, network })
}
