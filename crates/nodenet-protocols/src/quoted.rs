use crate::{
    Field, FragmentState, IpAddress, IpProtocol, Layer, ParseError, ParseMode, TcpFlags,
    UpperLayerState, parse_ipv4_packet, parse_ipv6_packet,
};

/// Transport evidence safely available inside a possibly truncated ICMP quote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotedTransport<'a> {
    Tcp {
        source_port: crate::Port,
        destination_port: crate::Port,
        sequence_number: u32,
        acknowledgment_number: Option<u32>,
        flags: Option<TcpFlags>,
        bytes: &'a [u8],
    },
    Udp {
        source_port: crate::Port,
        destination_port: crate::Port,
        declared_length: u16,
        checksum: u16,
        payload_prefix: &'a [u8],
    },
    IcmpEcho {
        message_type: u8,
        identifier: u16,
        sequence: u16,
        payload_prefix: &'a [u8],
    },
    Insufficient {
        protocol: IpProtocol,
        bytes: &'a [u8],
        required: usize,
    },
    NonFirstFragment {
        protocol: IpProtocol,
        bytes: &'a [u8],
    },
    Opaque {
        protocol: IpProtocol,
        bytes: &'a [u8],
    },
}

/// A length-first parsed IP packet quoted by an ICMP error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotedIpPacket<'a> {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub protocol: IpProtocol,
    pub fragment: FragmentState,
    pub complete: bool,
    pub transport: QuotedTransport<'a>,
}

/// Parses an IPv4 or IPv6 ICMP quote without accepting malformed headers.
///
/// Missing payload suffixes are accepted through the explicit compatible mode;
/// truncated base/extension headers and invalid IPv4 checksums remain errors.
/// Transport checksums are intentionally not required because ICMP quotations
/// routinely contain only the first eight transport bytes.
///
/// # Errors
///
/// Returns the stable L3 structural error or an unsupported version error.
pub fn parse_quoted_ip_packet(input: &[u8]) -> Result<QuotedIpPacket<'_>, ParseError> {
    let Some(first) = input.first() else {
        return Err(ParseError::Truncated {
            layer: Layer::Network,
            required: 1,
            actual: 0,
        });
    };
    match first >> 4 {
        4 => {
            let packet = parse_ipv4_packet(input, ParseMode::CompatibleIcmpQuote)?;
            Ok(QuotedIpPacket {
                source: IpAddress::V4(packet.source),
                destination: IpAddress::V4(packet.destination),
                protocol: packet.protocol,
                fragment: packet.fragment,
                complete: packet.complete,
                transport: classify_quote(packet.protocol, packet.payload, packet.fragment),
            })
        }
        6 => {
            let packet = parse_ipv6_packet(input, ParseMode::CompatibleIcmpQuote)?;
            let (protocol, bytes) = terminal_protocol_and_bytes(packet.upper_layer);
            Ok(QuotedIpPacket {
                source: IpAddress::V6(packet.source),
                destination: IpAddress::V6(packet.destination),
                protocol,
                fragment: packet.fragment,
                complete: packet.complete,
                transport: classify_quote(protocol, bytes, packet.fragment),
            })
        }
        _ => Err(ParseError::Unsupported {
            layer: Layer::Network,
            field: Field::Version,
        }),
    }
}

fn terminal_protocol_and_bytes(state: UpperLayerState<'_>) -> (IpProtocol, &[u8]) {
    match state {
        UpperLayerState::Reachable {
            protocol, payload, ..
        }
        | UpperLayerState::Insufficient {
            protocol, payload, ..
        }
        | UpperLayerState::NonFirstFragment {
            protocol, payload, ..
        }
        | UpperLayerState::Unknown {
            protocol, payload, ..
        } => (protocol, payload),
        UpperLayerState::Esp { payload, .. } => (IpProtocol::new(50), payload),
        UpperLayerState::NoNextHeader { trailing } => (IpProtocol::new(59), trailing),
    }
}

fn classify_quote(
    protocol: IpProtocol,
    bytes: &[u8],
    fragment: FragmentState,
) -> QuotedTransport<'_> {
    if matches!(fragment, FragmentState::NonFirst { .. }) {
        return QuotedTransport::NonFirstFragment { protocol, bytes };
    }
    match protocol.get() {
        6 if bytes.len() >= 8 => {
            let acknowledgment_number = bytes
                .get(8..12)
                .map(|value| u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            let flags = bytes.get(12..14).and_then(|value| {
                TcpFlags::from_bits((u16::from(value[0] & 1) << 8) | u16::from(value[1])).ok()
            });
            QuotedTransport::Tcp {
                source_port: crate::Port::new(u16::from_be_bytes([bytes[0], bytes[1]])),
                destination_port: crate::Port::new(u16::from_be_bytes([bytes[2], bytes[3]])),
                sequence_number: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                acknowledgment_number,
                flags,
                bytes,
            }
        }
        17 if bytes.len() >= 8 => QuotedTransport::Udp {
            source_port: crate::Port::new(u16::from_be_bytes([bytes[0], bytes[1]])),
            destination_port: crate::Port::new(u16::from_be_bytes([bytes[2], bytes[3]])),
            declared_length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload_prefix: &bytes[8..],
        },
        1 | 58 if bytes.len() >= 8 && is_echo(protocol.get(), bytes[0]) && bytes[1] == 0 => {
            QuotedTransport::IcmpEcho {
                message_type: bytes[0],
                identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
                sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
                payload_prefix: &bytes[8..],
            }
        }
        6 | 17 | 1 | 58 => QuotedTransport::Insufficient {
            protocol,
            bytes,
            required: 8,
        },
        _ => QuotedTransport::Opaque { protocol, bytes },
    }
}

const fn is_echo(protocol: u8, message_type: u8) -> bool {
    matches!((protocol, message_type), (1, 0 | 8) | (58, 128 | 129))
}
