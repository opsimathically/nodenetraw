use etherparse::{LaxSlicedPacket, SlicedPacket, err};

use crate::{
    Field, Layer, MAX_ETHERNET_FRAME_LENGTH, MAX_IP_PACKET_LENGTH, MAX_IPV6_EXTENSION_BYTES,
    MAX_IPV6_EXTENSION_HEADER_COUNT, MAX_VLAN_HEADER_COUNT, ParseError, ParseMode, Resource,
};

const ETHERNET_HEADER_LENGTH: usize = 14;
const VLAN_HEADER_LENGTH: usize = 4;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_PROVIDER_BRIDGING: u16 = 0x88a8;
const IPV6_HEADER_LENGTH: usize = 40;
const IP_NUMBER_HOP_BY_HOP: u8 = 0;
const IP_NUMBER_ROUTING: u8 = 43;
const IP_NUMBER_FRAGMENT: u8 = 44;
const IP_NUMBER_AUTHENTICATION: u8 = 51;
const IP_NUMBER_DESTINATION_OPTIONS: u8 = 60;

/// Identifies the first header in an input slice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PacketStart {
    Ethernet,
    Ip,
}

/// Result of bounded structural inspection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParseStatus {
    Complete,
    /// An explicitly compatible ICMP quote ended at the named layer.
    IncompleteQuote {
        layer: Layer,
    },
}

/// Performs allocation-free structural inspection behind stable project errors.
///
/// `CompatibleIcmpQuote` is accepted only for an IP-starting slice and tolerates
/// truncation only. Malformed content remains an error and strict mode never
/// retries through the compatible parser.
///
/// # Errors
///
/// Returns a structured error when the input exceeds its bound, is truncated in
/// strict mode, is malformed, or requests quote compatibility for Ethernet.
pub fn inspect_packet(
    input: &[u8],
    start: PacketStart,
    mode: ParseMode,
) -> Result<ParseStatus, ParseError> {
    enforce_input_limit(input.len(), start)?;
    enforce_structural_limits(input, start)?;

    match (start, mode) {
        (PacketStart::Ethernet | PacketStart::Ip, ParseMode::Strict) => {
            inspect_strict(input, start)
        }
        (PacketStart::Ip, ParseMode::CompatibleIcmpQuote) => inspect_quote(input),
        (PacketStart::Ethernet, ParseMode::CompatibleIcmpQuote) => Err(ParseError::Unsupported {
            layer: Layer::Link,
            field: Field::HeaderLength,
        }),
    }
}

fn enforce_structural_limits(input: &[u8], start: PacketStart) -> Result<(), ParseError> {
    let ip_offset = match start {
        PacketStart::Ip => 0,
        PacketStart::Ethernet => {
            let Some(mut ether_type) = read_u16(input, 12) else {
                return Ok(());
            };
            let mut offset = ETHERNET_HEADER_LENGTH;
            let mut vlan_count = 0;
            while matches!(ether_type, ETHER_TYPE_VLAN | ETHER_TYPE_PROVIDER_BRIDGING) {
                vlan_count += 1;
                if vlan_count > MAX_VLAN_HEADER_COUNT {
                    return Err(ParseError::LimitExceeded {
                        resource: Resource::VlanHeaders,
                        actual: vlan_count,
                        maximum: MAX_VLAN_HEADER_COUNT,
                    });
                }
                let Some(next_ether_type) = read_u16(input, offset + 2) else {
                    return Ok(());
                };
                ether_type = next_ether_type;
                offset += VLAN_HEADER_LENGTH;
            }
            if ether_type != ETHER_TYPE_IPV6 {
                return Ok(());
            }
            offset
        }
    };

    enforce_ipv6_extension_limits(input, ip_offset)
}

fn enforce_ipv6_extension_limits(input: &[u8], offset: usize) -> Result<(), ParseError> {
    let Some(header) = input.get(offset..offset.saturating_add(IPV6_HEADER_LENGTH)) else {
        return Ok(());
    };
    if header[0] >> 4 != 6 {
        return Ok(());
    }

    let payload_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let mut next_header = header[6];
    if payload_length == 0 && next_header == IP_NUMBER_HOP_BY_HOP {
        return Err(ParseError::Unsupported {
            layer: Layer::Ipv6,
            field: Field::PacketLength,
        });
    }

    let declared_end = offset
        .checked_add(IPV6_HEADER_LENGTH)
        .and_then(|start| start.checked_add(payload_length))
        .ok_or(ParseError::ArithmeticOverflow {
            field: Field::PacketLength,
        })?;
    let available_end = input.len().min(declared_end);
    let mut cursor = offset + IPV6_HEADER_LENGTH;
    let mut header_count = 0_usize;
    let mut extension_bytes = 0_usize;

    while is_bounded_ipv6_extension(next_header) {
        header_count += 1;
        if header_count > MAX_IPV6_EXTENSION_HEADER_COUNT {
            return Err(ParseError::LimitExceeded {
                resource: Resource::Ipv6ExtensionHeaders,
                actual: header_count,
                maximum: MAX_IPV6_EXTENSION_HEADER_COUNT,
            });
        }

        let Some(&following_header) = input.get(cursor).filter(|_| cursor < available_end) else {
            return Ok(());
        };
        let encoded_length = match next_header {
            IP_NUMBER_FRAGMENT => 8,
            IP_NUMBER_AUTHENTICATION => {
                let Some(&length_field) =
                    input.get(cursor + 1).filter(|_| cursor + 1 < available_end)
                else {
                    return Ok(());
                };
                (usize::from(length_field) + 2) * 4
            }
            _ => {
                let Some(&length_field) =
                    input.get(cursor + 1).filter(|_| cursor + 1 < available_end)
                else {
                    return Ok(());
                };
                (usize::from(length_field) + 1) * 8
            }
        };
        extension_bytes =
            extension_bytes
                .checked_add(encoded_length)
                .ok_or(ParseError::ArithmeticOverflow {
                    field: Field::ExtensionLength,
                })?;
        if extension_bytes > MAX_IPV6_EXTENSION_BYTES {
            return Err(ParseError::LimitExceeded {
                resource: Resource::Ipv6ExtensionBytes,
                actual: extension_bytes,
                maximum: MAX_IPV6_EXTENSION_BYTES,
            });
        }
        let Some(end) = cursor.checked_add(encoded_length) else {
            return Err(ParseError::ArithmeticOverflow {
                field: Field::ExtensionLength,
            });
        };
        if end > available_end {
            return Ok(());
        }
        next_header = following_header;
        cursor = end;
    }

    Ok(())
}

const fn is_bounded_ipv6_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        IP_NUMBER_HOP_BY_HOP
            | IP_NUMBER_ROUTING
            | IP_NUMBER_FRAGMENT
            | IP_NUMBER_AUTHENTICATION
            | IP_NUMBER_DESTINATION_OPTIONS
    )
}

fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    let bytes = input.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn enforce_input_limit(length: usize, start: PacketStart) -> Result<(), ParseError> {
    let (maximum, resource) = match start {
        PacketStart::Ethernet => (MAX_ETHERNET_FRAME_LENGTH, Resource::FrameBytes),
        PacketStart::Ip => (MAX_IP_PACKET_LENGTH, Resource::IpPacketBytes),
    };
    if length > maximum {
        return Err(ParseError::LimitExceeded {
            resource,
            actual: length,
            maximum,
        });
    }
    Ok(())
}

fn inspect_strict(input: &[u8], start: PacketStart) -> Result<ParseStatus, ParseError> {
    let result = match start {
        PacketStart::Ethernet => SlicedPacket::from_ethernet(input),
        PacketStart::Ip => SlicedPacket::from_ip(input),
    };
    result.map_or_else(
        |error| Err(map_slice_error(error)),
        |_| Ok(ParseStatus::Complete),
    )
}

fn inspect_quote(input: &[u8]) -> Result<ParseStatus, ParseError> {
    match LaxSlicedPacket::from_ip(input) {
        Err(err::ip::LaxHeaderSliceError::Len(error)) => Ok(ParseStatus::IncompleteQuote {
            layer: map_layer(error.layer),
        }),
        Err(err::ip::LaxHeaderSliceError::Content(_)) => Err(ParseError::Malformed {
            layer: Layer::Network,
            field: Field::HeaderLength,
        }),
        Ok(packet) => match packet.stop_err {
            None => {
                let used_slice_fallback = packet
                    .net
                    .as_ref()
                    .and_then(etherparse::LaxNetSlice::ip_payload_ref)
                    .is_some_and(|payload| payload.len_source == etherparse::LenSource::Slice);
                if used_slice_fallback {
                    Ok(ParseStatus::IncompleteQuote {
                        layer: Layer::Payload,
                    })
                } else {
                    Ok(ParseStatus::Complete)
                }
            }
            Some((err::packet::SliceError::Len(error), layer)) => {
                Ok(ParseStatus::IncompleteQuote {
                    layer: map_layer(layer).max_specific(map_layer(error.layer)),
                })
            }
            Some((error, layer)) => Err(ParseError::Malformed {
                layer: map_content_layer(&error).max_specific(map_layer(layer)),
                field: Field::HeaderLength,
            }),
        },
    }
}

fn map_slice_error(error: err::packet::SliceError) -> ParseError {
    match error {
        err::packet::SliceError::Len(error) => ParseError::Truncated {
            layer: map_layer(error.layer),
            required: error.required_len,
            actual: error.len,
        },
        error => ParseError::Malformed {
            layer: map_content_layer(&error),
            field: Field::HeaderLength,
        },
    }
}

fn map_content_layer(error: &err::packet::SliceError) -> Layer {
    match error {
        err::packet::SliceError::Len(error) => map_layer(error.layer),
        err::packet::SliceError::LinuxSll(_) | err::packet::SliceError::Macsec(_) => Layer::Link,
        err::packet::SliceError::Ip(_) => Layer::Network,
        err::packet::SliceError::Ipv4(_) | err::packet::SliceError::Ipv4Exts(_) => Layer::Ipv4,
        err::packet::SliceError::Ipv6(_) => Layer::Ipv6,
        err::packet::SliceError::Ipv6Exts(_) => Layer::Ipv6Extension,
        err::packet::SliceError::Tcp(_) => Layer::Tcp,
    }
}

fn map_layer(layer: err::Layer) -> Layer {
    use err::Layer as EtherLayer;

    match layer {
        EtherLayer::LinuxSllHeader
        | EtherLayer::Ethernet2Header
        | EtherLayer::EtherPayload
        | EtherLayer::MacsecHeader
        | EtherLayer::MacsecPacket => Layer::Link,
        EtherLayer::VlanHeader => Layer::Vlan,
        EtherLayer::IpHeader => Layer::Network,
        EtherLayer::Ipv4Header | EtherLayer::Ipv4Packet | EtherLayer::IpAuthHeader => Layer::Ipv4,
        EtherLayer::Ipv6Header | EtherLayer::Ipv6Packet => Layer::Ipv6,
        EtherLayer::Ipv6ExtHeader
        | EtherLayer::Ipv6HopByHopHeader
        | EtherLayer::Ipv6DestOptionsHeader
        | EtherLayer::Ipv6RouteHeader
        | EtherLayer::Ipv6FragHeader => Layer::Ipv6Extension,
        EtherLayer::UdpHeader | EtherLayer::UdpPayload => Layer::Udp,
        EtherLayer::TcpHeader => Layer::Tcp,
        EtherLayer::Icmpv4 | EtherLayer::Icmpv4Timestamp | EtherLayer::Icmpv4TimestampReply => {
            Layer::Icmpv4
        }
        EtherLayer::Icmpv6 => Layer::Icmpv6,
        EtherLayer::Arp => Layer::Arp,
    }
}

trait MostSpecificLayer {
    fn max_specific(self, fallback: Self) -> Self;
}

impl MostSpecificLayer for Layer {
    fn max_specific(self, fallback: Self) -> Self {
        if self == Layer::Network {
            fallback
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_mode_is_not_a_generic_ethernet_fallback() {
        assert_eq!(
            inspect_packet(&[], PacketStart::Ethernet, ParseMode::CompatibleIcmpQuote),
            Err(ParseError::Unsupported {
                layer: Layer::Link,
                field: Field::HeaderLength,
            })
        );
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        let input = vec![0; MAX_IP_PACKET_LENGTH + 1];
        assert!(matches!(
            inspect_packet(&input, PacketStart::Ip, ParseMode::Strict),
            Err(ParseError::LimitExceeded {
                resource: Resource::IpPacketBytes,
                ..
            })
        ));
    }
}
