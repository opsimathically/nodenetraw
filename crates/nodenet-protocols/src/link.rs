use crate::{
    BuildError, EtherType, Field, Layer, MAX_ETHERNET_FRAME_LENGTH, MAX_VLAN_HEADER_COUNT,
    MacAddress, PacketKind, PacketLength, ParseError,
};

pub const ETHER_TYPE_IPV4: EtherType = EtherType::new(0x0800);
pub const ETHER_TYPE_ARP: EtherType = EtherType::new(0x0806);
pub const ETHER_TYPE_VLAN: EtherType = EtherType::new(0x8100);
pub const ETHER_TYPE_IPV6: EtherType = EtherType::new(0x86dd);
pub const ETHER_TYPE_PROVIDER_BRIDGING: EtherType = EtherType::new(0x88a8);

const ETHERNET_HEADER_LENGTH: usize = 14;
const VLAN_HEADER_LENGTH: usize = 4;

/// Supported IEEE VLAN tag protocols.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VlanTagProtocol {
    Dot1Q,
    ProviderBridging,
}

impl VlanTagProtocol {
    #[must_use]
    pub const fn ether_type(self) -> EtherType {
        match self {
            Self::Dot1Q => ETHER_TYPE_VLAN,
            Self::ProviderBridging => ETHER_TYPE_PROVIDER_BRIDGING,
        }
    }

    const fn from_ether_type(value: EtherType) -> Option<Self> {
        match value.get() {
            0x8100 => Some(Self::Dot1Q),
            0x88a8 => Some(Self::ProviderBridging),
            _ => None,
        }
    }
}

/// A checked 802.1Q/802.1ad VLAN tag.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VlanTag {
    protocol: VlanTagProtocol,
    priority_code_point: u8,
    drop_eligible: bool,
    identifier: u16,
}

impl VlanTag {
    /// Creates a checked VLAN tag.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::InvalidValue`] when PCP exceeds 7 or VID exceeds
    /// 4095.
    pub const fn new(
        protocol: VlanTagProtocol,
        priority_code_point: u8,
        drop_eligible: bool,
        identifier: u16,
    ) -> Result<Self, BuildError> {
        if priority_code_point > 7 {
            return Err(BuildError::InvalidValue {
                field: Field::VlanPriority,
            });
        }
        if identifier > 0x0fff {
            return Err(BuildError::InvalidValue {
                field: Field::VlanIdentifier,
            });
        }
        Ok(Self {
            protocol,
            priority_code_point,
            drop_eligible,
            identifier,
        })
    }

    #[must_use]
    pub const fn protocol(self) -> VlanTagProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn priority_code_point(self) -> u8 {
        self.priority_code_point
    }

    #[must_use]
    pub const fn drop_eligible(self) -> bool {
        self.drop_eligible
    }

    #[must_use]
    pub const fn identifier(self) -> u16 {
        self.identifier
    }

    fn control_information(self) -> u16 {
        (u16::from(self.priority_code_point) << 13)
            | (if self.drop_eligible { 1 << 12 } else { 0 })
            | self.identifier
    }

    fn from_wire(protocol: VlanTagProtocol, value: u16) -> Self {
        Self {
            protocol,
            priority_code_point: u8::try_from((value >> 13) & 0x7)
                .expect("three-bit VLAN priority fits u8"),
            drop_eligible: value & 0x1000 != 0,
            identifier: value & 0x0fff,
        }
    }
}

/// Zero, one, or two VLAN tags in outer-to-inner wire order.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum VlanStack {
    #[default]
    None,
    One(VlanTag),
    Two([VlanTag; 2]),
}

impl VlanStack {
    #[must_use]
    pub const fn as_slice(&self) -> &[VlanTag] {
        match self {
            Self::None => &[],
            Self::One(tag) => core::slice::from_ref(tag),
            Self::Two(tags) => tags,
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.as_slice().len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// An Ethernet II header with its bounded VLAN stack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EthernetHeader {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub vlan: VlanStack,
    pub ether_type: EtherType,
}

impl EthernetHeader {
    #[must_use]
    pub const fn encoded_length(&self) -> usize {
        ETHERNET_HEADER_LENGTH + self.vlan.len() * VLAN_HEADER_LENGTH
    }
}

/// A borrowed Ethernet frame builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
}

impl EthernetFrame<'_> {
    /// Returns the complete checked frame length.
    ///
    /// # Errors
    ///
    /// Returns an overflow or Ethernet frame-ceiling error.
    pub const fn required_length(&self) -> Result<PacketLength, BuildError> {
        let Some(length) = self.header.encoded_length().checked_add(self.payload.len()) else {
            return Err(BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            });
        };
        PacketLength::new(length, PacketKind::Ethernet)
    }

    /// Encodes into caller-owned storage after all fallible checks complete.
    ///
    /// # Errors
    ///
    /// Returns a length or short-buffer error without modifying `output`.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.required_length()?.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }

        let encoded = &mut output[..required];
        encoded[0..6].copy_from_slice(&self.header.destination.octets());
        encoded[6..12].copy_from_slice(&self.header.source.octets());
        let tags = self.header.vlan.as_slice();
        let first_type = tags
            .first()
            .map_or(self.header.ether_type, |tag| tag.protocol().ether_type());
        encoded[12..14].copy_from_slice(&first_type.get().to_be_bytes());
        let mut offset = ETHERNET_HEADER_LENGTH;
        for (index, tag) in tags.iter().copied().enumerate() {
            encoded[offset..offset + 2].copy_from_slice(&tag.control_information().to_be_bytes());
            let next_type = tags
                .get(index + 1)
                .map_or(self.header.ether_type, |next| next.protocol().ether_type());
            encoded[offset + 2..offset + 4].copy_from_slice(&next_type.get().to_be_bytes());
            offset += VLAN_HEADER_LENGTH;
        }
        encoded[offset..].copy_from_slice(self.payload);
        Ok(encoded)
    }

    /// Encodes an exactly sized owned frame.
    ///
    /// # Errors
    ///
    /// Returns a length validation error before allocation.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0; required];
        self.write_into(&mut output)?;
        Ok(output)
    }
}

/// A validated borrowed Ethernet frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedEthernetFrame<'a> {
    pub header: EthernetHeader,
    pub payload: &'a [u8],
    pub header_length: usize,
}

/// Parses an Ethernet II frame and at most two supported VLAN tags.
///
/// # Errors
///
/// Returns truncation, excessive nesting, or frame-ceiling errors.
pub fn parse_ethernet_frame(input: &[u8]) -> Result<ParsedEthernetFrame<'_>, ParseError> {
    if input.len() > MAX_ETHERNET_FRAME_LENGTH {
        return Err(ParseError::LimitExceeded {
            resource: crate::Resource::FrameBytes,
            actual: input.len(),
            maximum: MAX_ETHERNET_FRAME_LENGTH,
        });
    }
    require_length(input, ETHERNET_HEADER_LENGTH, Layer::Link)?;
    let destination = MacAddress::new([input[0], input[1], input[2], input[3], input[4], input[5]]);
    let source = MacAddress::new([input[6], input[7], input[8], input[9], input[10], input[11]]);
    let mut ether_type = EtherType::new(u16::from_be_bytes([input[12], input[13]]));
    let mut tags = [None, None];
    let mut count = 0;
    let mut offset = ETHERNET_HEADER_LENGTH;

    while let Some(protocol) = VlanTagProtocol::from_ether_type(ether_type) {
        if count == MAX_VLAN_HEADER_COUNT {
            return Err(ParseError::LimitExceeded {
                resource: crate::Resource::VlanHeaders,
                actual: count + 1,
                maximum: MAX_VLAN_HEADER_COUNT,
            });
        }
        require_length(input, offset + VLAN_HEADER_LENGTH, Layer::Vlan)?;
        let control = u16::from_be_bytes([input[offset], input[offset + 1]]);
        tags[count] = Some(VlanTag::from_wire(protocol, control));
        ether_type = EtherType::new(u16::from_be_bytes([input[offset + 2], input[offset + 3]]));
        count += 1;
        offset += VLAN_HEADER_LENGTH;
    }

    let vlan = match tags {
        [None, None] => VlanStack::None,
        [Some(tag), None] => VlanStack::One(tag),
        [Some(outer), Some(inner)] => VlanStack::Two([outer, inner]),
        [None, Some(_)] => unreachable!("tags are filled in wire order"),
    };
    Ok(ParsedEthernetFrame {
        header: EthernetHeader {
            destination,
            source,
            vlan,
            ether_type,
        },
        payload: &input[offset..],
        header_length: offset,
    })
}

fn require_length(input: &[u8], required: usize, layer: Layer) -> Result<(), ParseError> {
    if input.len() < required {
        return Err(ParseError::Truncated {
            layer,
            required,
            actual: input.len(),
        });
    }
    Ok(())
}
