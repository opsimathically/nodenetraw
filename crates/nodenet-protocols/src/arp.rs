use crate::{
    BuildError, EtherType, Field, Ipv4Address, Layer, MAX_ETHERNET_FRAME_LENGTH, MacAddress,
    ParseError, Resource,
};

const ARP_ETHERNET_HARDWARE_TYPE: u16 = 1;
const ARP_IPV4_PROTOCOL_TYPE: u16 = 0x0800;
const ARP_ETHERNET_ADDRESS_LENGTH: u8 = 6;
const ARP_IPV4_ADDRESS_LENGTH: u8 = 4;
const ARP_FIXED_LENGTH: usize = 8;
const ARP_ETHERNET_IPV4_LENGTH: usize = 28;

/// Supported Ethernet/IPv4 ARP operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArpEthernetIpv4Operation {
    Request,
    Reply,
}

impl ArpEthernetIpv4Operation {
    const fn wire_value(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
        }
    }

    const fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Request),
            2 => Some(Self::Reply),
            _ => None,
        }
    }
}

/// A canonical Ethernet/IPv4 ARP request or reply.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ArpEthernetIpv4Packet {
    pub operation: ArpEthernetIpv4Operation,
    pub sender_hardware_address: MacAddress,
    pub sender_protocol_address: Ipv4Address,
    pub target_hardware_address: MacAddress,
    pub target_protocol_address: Ipv4Address,
}

impl ArpEthernetIpv4Packet {
    #[must_use]
    pub const fn required_length(self) -> usize {
        ARP_ETHERNET_IPV4_LENGTH
    }

    /// Encodes the canonical 28-byte ARP packet.
    ///
    /// # Errors
    ///
    /// Returns a short-buffer error without modifying `output`.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        if output.len() < ARP_ETHERNET_IPV4_LENGTH {
            return Err(BuildError::BufferTooSmall {
                required: ARP_ETHERNET_IPV4_LENGTH,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..ARP_ETHERNET_IPV4_LENGTH];
        encode_ethernet_ipv4(self, encoded);
        Ok(encoded)
    }

    /// Encodes an owned canonical ARP packet.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        let mut output = vec![0; ARP_ETHERNET_IPV4_LENGTH];
        encode_ethernet_ipv4(self, &mut output);
        output
    }
}

/// A structurally valid ARP format not interpreted as Ethernet/IPv4 request/reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownArpPacket<'a> {
    pub hardware_type: u16,
    pub protocol_type: EtherType,
    pub hardware_address_length: u8,
    pub protocol_address_length: u8,
    pub operation: u16,
    pub sender_hardware_address: &'a [u8],
    pub sender_protocol_address: &'a [u8],
    pub target_hardware_address: &'a [u8],
    pub target_protocol_address: &'a [u8],
}

/// A typed known ARP packet or an explicitly preserved unknown combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedArpPacket<'a> {
    EthernetIpv4(ArpEthernetIpv4Packet),
    Unknown(UnknownArpPacket<'a>),
}

/// Parses an ARP packet using its explicit hardware/protocol address lengths.
///
/// # Errors
///
/// Returns truncation or checked-length overflow without guessing a format.
pub fn parse_arp_packet(input: &[u8]) -> Result<ParsedArpPacket<'_>, ParseError> {
    if input.len() > MAX_ETHERNET_FRAME_LENGTH {
        return Err(ParseError::LimitExceeded {
            resource: Resource::FrameBytes,
            actual: input.len(),
            maximum: MAX_ETHERNET_FRAME_LENGTH,
        });
    }
    if input.len() < ARP_FIXED_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Arp,
            required: ARP_FIXED_LENGTH,
            actual: input.len(),
        });
    }
    let hardware_type = u16::from_be_bytes([input[0], input[1]]);
    let protocol_type = EtherType::new(u16::from_be_bytes([input[2], input[3]]));
    let hardware_address_length = input[4];
    let protocol_address_length = input[5];
    let operation = u16::from_be_bytes([input[6], input[7]]);
    let pair_length = usize::from(hardware_address_length)
        .checked_add(usize::from(protocol_address_length))
        .ok_or(ParseError::ArithmeticOverflow {
            field: Field::AddressLength,
        })?;
    let required = pair_length
        .checked_mul(2)
        .and_then(|addresses| ARP_FIXED_LENGTH.checked_add(addresses))
        .ok_or(ParseError::ArithmeticOverflow {
            field: Field::PacketLength,
        })?;
    if input.len() < required {
        return Err(ParseError::Truncated {
            layer: Layer::Arp,
            required,
            actual: input.len(),
        });
    }

    let hardware_length = usize::from(hardware_address_length);
    let protocol_length = usize::from(protocol_address_length);
    let sender_hardware_end = ARP_FIXED_LENGTH + hardware_length;
    let sender_protocol_end = sender_hardware_end + protocol_length;
    let target_hardware_end = sender_protocol_end + hardware_length;
    let target_protocol_end = target_hardware_end + protocol_length;
    let unknown = UnknownArpPacket {
        hardware_type,
        protocol_type,
        hardware_address_length,
        protocol_address_length,
        operation,
        sender_hardware_address: &input[ARP_FIXED_LENGTH..sender_hardware_end],
        sender_protocol_address: &input[sender_hardware_end..sender_protocol_end],
        target_hardware_address: &input[sender_protocol_end..target_hardware_end],
        target_protocol_address: &input[target_hardware_end..target_protocol_end],
    };

    let Some(known_operation) = ArpEthernetIpv4Operation::from_wire(operation) else {
        return Ok(ParsedArpPacket::Unknown(unknown));
    };
    if hardware_type != ARP_ETHERNET_HARDWARE_TYPE
        || protocol_type.get() != ARP_IPV4_PROTOCOL_TYPE
        || hardware_address_length != ARP_ETHERNET_ADDRESS_LENGTH
        || protocol_address_length != ARP_IPV4_ADDRESS_LENGTH
    {
        return Ok(ParsedArpPacket::Unknown(unknown));
    }

    Ok(ParsedArpPacket::EthernetIpv4(ArpEthernetIpv4Packet {
        operation: known_operation,
        sender_hardware_address: mac_from_slice(unknown.sender_hardware_address),
        sender_protocol_address: ipv4_from_slice(unknown.sender_protocol_address),
        target_hardware_address: mac_from_slice(unknown.target_hardware_address),
        target_protocol_address: ipv4_from_slice(unknown.target_protocol_address),
    }))
}

fn encode_ethernet_ipv4(packet: ArpEthernetIpv4Packet, encoded: &mut [u8]) {
    encoded[0..2].copy_from_slice(&ARP_ETHERNET_HARDWARE_TYPE.to_be_bytes());
    encoded[2..4].copy_from_slice(&ARP_IPV4_PROTOCOL_TYPE.to_be_bytes());
    encoded[4] = ARP_ETHERNET_ADDRESS_LENGTH;
    encoded[5] = ARP_IPV4_ADDRESS_LENGTH;
    encoded[6..8].copy_from_slice(&packet.operation.wire_value().to_be_bytes());
    encoded[8..14].copy_from_slice(&packet.sender_hardware_address.octets());
    encoded[14..18].copy_from_slice(&packet.sender_protocol_address.octets());
    encoded[18..24].copy_from_slice(&packet.target_hardware_address.octets());
    encoded[24..28].copy_from_slice(&packet.target_protocol_address.octets());
}

fn mac_from_slice(input: &[u8]) -> MacAddress {
    MacAddress::new([input[0], input[1], input[2], input[3], input[4], input[5]])
}

fn ipv4_from_slice(input: &[u8]) -> Ipv4Address {
    Ipv4Address::new([input[0], input[1], input[2], input[3]])
}
