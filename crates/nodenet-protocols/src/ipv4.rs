use crate::{
    BuildError, Field, FragmentState, IpProtocol, Ipv4Address, Layer, MAX_IP_PACKET_LENGTH,
    PacketKind, PacketLength, ParseError, ParseMode, Resource, UpperLayerState,
    compute_internet_checksum, network::classify_upper_layer, validate_internet_checksum,
};

const IPV4_MIN_HEADER_LENGTH: usize = 20;
const IPV4_MAX_HEADER_LENGTH: usize = 60;
const IPV4_MAX_PACKET_LENGTH: usize = 65_535;
const IPV4_MAX_FRAGMENT_OFFSET: u16 = 0x1fff;

/// Non-fatal IPv4 conformance observations preserved separately from structure.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ipv4Conformance(u8);

impl Ipv4Conformance {
    pub const RESERVED_FLAG_SET: Self = Self(1 << 0);
    pub const NONZERO_OPTION_PADDING: Self = Self(1 << 1);

    #[must_use]
    pub const fn contains(self, issue: Self) -> bool {
        self.0 & issue.0 == issue.0
    }

    #[must_use]
    pub const fn is_canonical(self) -> bool {
        self.0 == 0
    }

    const fn insert(&mut self, issue: Self) {
        self.0 |= issue.0;
    }
}

/// A borrowed canonical IPv4 packet builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Packet<'a> {
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: IpProtocol,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl Ipv4Packet<'_> {
    /// Returns the checked complete IPv4 packet length.
    ///
    /// # Errors
    ///
    /// Returns an invalid field, overflow, or IPv4 length-ceiling error.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        self.validate()?;
        let header_length = IPV4_MIN_HEADER_LENGTH + self.options.len();
        let total = header_length.checked_add(self.payload.len()).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::TotalLength,
            },
        )?;
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Encodes a complete IPv4 packet and computes its header checksum.
    ///
    /// # Errors
    ///
    /// Returns before modifying `output` when a field, length, option, fragment,
    /// or buffer check fails.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.required_length()?.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..required];
        encode_ipv4(self, encoded);
        Ok(encoded)
    }

    /// Builds an exactly sized owned IPv4 packet.
    ///
    /// # Errors
    ///
    /// Returns a validation error before allocation.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0; required];
        encode_ipv4(self, &mut output);
        Ok(output)
    }

    fn validate(&self) -> Result<(), BuildError> {
        if self.dscp > 0x3f {
            return Err(BuildError::InvalidValue { field: Field::Dscp });
        }
        if self.ecn > 0x03 {
            return Err(BuildError::InvalidValue { field: Field::Ecn });
        }
        if self.options.len() > IPV4_MAX_HEADER_LENGTH - IPV4_MIN_HEADER_LENGTH
            || !self.options.len().is_multiple_of(4)
            || !ipv4_options_are_canonical(self.options)
        {
            return Err(BuildError::InvalidValue {
                field: Field::OptionLength,
            });
        }
        if self.fragment_offset > IPV4_MAX_FRAGMENT_OFFSET {
            return Err(BuildError::InvalidValue {
                field: Field::FragmentOffset,
            });
        }
        if self.dont_fragment && (self.more_fragments || self.fragment_offset != 0) {
            return Err(BuildError::InvalidValue {
                field: Field::Flags,
            });
        }
        if self.more_fragments && !self.payload.len().is_multiple_of(8) {
            return Err(BuildError::InvalidValue {
                field: Field::PayloadLength,
            });
        }
        let total = IPV4_MIN_HEADER_LENGTH
            .checked_add(self.options.len())
            .and_then(|header| header.checked_add(self.payload.len()))
            .ok_or(BuildError::ArithmeticOverflow {
                field: Field::TotalLength,
            })?;
        if total > IPV4_MAX_PACKET_LENGTH {
            return Err(BuildError::LengthExceedsLimit {
                actual: total,
                maximum: IPV4_MAX_PACKET_LENGTH,
                kind: PacketKind::Ip,
            });
        }
        Ok(())
    }
}

/// A borrowed validated IPv4 packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIpv4Packet<'a> {
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: IpProtocol,
    pub source: Ipv4Address,
    pub destination: Ipv4Address,
    pub options: &'a [u8],
    pub payload: &'a [u8],
    pub trailing: &'a [u8],
    pub declared_total_length: usize,
    pub complete: bool,
    pub fragment: FragmentState,
    pub upper_layer: UpperLayerState<'a>,
    pub conformance: Ipv4Conformance,
}

/// Parses and checksum-validates an IPv4 packet.
///
/// Compatible mode permits only a missing suffix after the complete validated
/// header. It never accepts a truncated or malformed header.
///
/// # Errors
///
/// Returns structured version, IHL, option, length, flag, checksum, or
/// truncation errors.
#[allow(
    clippy::too_many_lines,
    reason = "length-first IPv4 validation is kept in wire order for auditability"
)]
pub fn parse_ipv4_packet(
    input: &[u8],
    mode: ParseMode,
) -> Result<ParsedIpv4Packet<'_>, ParseError> {
    if input.len() > MAX_IP_PACKET_LENGTH {
        return Err(ParseError::LimitExceeded {
            resource: Resource::IpPacketBytes,
            actual: input.len(),
            maximum: MAX_IP_PACKET_LENGTH,
        });
    }
    if input.len() < IPV4_MIN_HEADER_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Ipv4,
            required: IPV4_MIN_HEADER_LENGTH,
            actual: input.len(),
        });
    }
    if input[0] >> 4 != 4 {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv4,
            field: Field::Version,
        });
    }
    let ihl = usize::from(input[0] & 0x0f);
    if ihl < 5 {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv4,
            field: Field::HeaderLength,
        });
    }
    let header_length = ihl * 4;
    if input.len() < header_length {
        return Err(ParseError::Truncated {
            layer: Layer::Ipv4,
            required: header_length,
            actual: input.len(),
        });
    }
    let declared_total_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
    if declared_total_length < header_length {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv4,
            field: Field::TotalLength,
        });
    }
    let complete = input.len() >= declared_total_length;
    if !complete && mode == ParseMode::Strict {
        return Err(ParseError::Truncated {
            layer: Layer::Ipv4,
            required: declared_total_length,
            actual: input.len(),
        });
    }
    if !validate_internet_checksum(&input[..header_length]) {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv4,
            field: Field::Checksum,
        });
    }

    let options = &input[IPV4_MIN_HEADER_LENGTH..header_length];
    let mut conformance = validate_ipv4_options(options)?;
    let flags_fragment = u16::from_be_bytes([input[6], input[7]]);
    let reserved = flags_fragment & 0x8000 != 0;
    let dont_fragment = flags_fragment & 0x4000 != 0;
    let more_fragments = flags_fragment & 0x2000 != 0;
    let fragment_offset = flags_fragment & IPV4_MAX_FRAGMENT_OFFSET;
    if reserved {
        conformance.insert(Ipv4Conformance::RESERVED_FLAG_SET);
    }
    if dont_fragment && (more_fragments || fragment_offset != 0) {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv4,
            field: Field::Flags,
        });
    }
    let declared_payload_length = declared_total_length - header_length;
    if more_fragments && declared_payload_length % 8 != 0 {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv4,
            field: Field::PayloadLength,
        });
    }
    let fragment = if fragment_offset == 0 {
        if more_fragments {
            FragmentState::First {
                more_fragments: true,
            }
        } else {
            FragmentState::Unfragmented
        }
    } else {
        FragmentState::NonFirst {
            offset_units: fragment_offset,
            more_fragments,
        }
    };
    let packet_end = input.len().min(declared_total_length);
    let payload = &input[header_length..packet_end];
    let trailing = if complete {
        &input[declared_total_length..]
    } else {
        &[]
    };
    let protocol = IpProtocol::new(input[9]);
    Ok(ParsedIpv4Packet {
        dscp: input[1] >> 2,
        ecn: input[1] & 0x03,
        identification: u16::from_be_bytes([input[4], input[5]]),
        dont_fragment,
        more_fragments,
        fragment_offset,
        time_to_live: input[8],
        protocol,
        source: Ipv4Address::new([input[12], input[13], input[14], input[15]]),
        destination: Ipv4Address::new([input[16], input[17], input[18], input[19]]),
        options,
        payload,
        trailing,
        declared_total_length,
        complete,
        fragment,
        upper_layer: classify_upper_layer(protocol, payload, fragment, false),
        conformance,
    })
}

fn encode_ipv4(packet: Ipv4Packet<'_>, encoded: &mut [u8]) {
    let header_length = IPV4_MIN_HEADER_LENGTH + packet.options.len();
    let total_length = u16::try_from(encoded.len()).unwrap_or(u16::MAX);
    let ihl = u8::try_from(header_length / 4).unwrap_or(15);
    encoded[0] = 0x40 | ihl;
    encoded[1] = (packet.dscp << 2) | packet.ecn;
    encoded[2..4].copy_from_slice(&total_length.to_be_bytes());
    encoded[4..6].copy_from_slice(&packet.identification.to_be_bytes());
    let flags_fragment = (if packet.dont_fragment { 0x4000 } else { 0 })
        | (if packet.more_fragments { 0x2000 } else { 0 })
        | packet.fragment_offset;
    encoded[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
    encoded[8] = packet.time_to_live;
    encoded[9] = packet.protocol.get();
    encoded[10..12].fill(0);
    encoded[12..16].copy_from_slice(&packet.source.octets());
    encoded[16..20].copy_from_slice(&packet.destination.octets());
    encoded[IPV4_MIN_HEADER_LENGTH..header_length].copy_from_slice(packet.options);
    encoded[header_length..].copy_from_slice(packet.payload);
    let checksum = compute_internet_checksum(&encoded[..header_length]);
    encoded[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn ipv4_options_are_canonical(options: &[u8]) -> bool {
    validate_ipv4_options(options).is_ok_and(Ipv4Conformance::is_canonical)
}

fn validate_ipv4_options(options: &[u8]) -> Result<Ipv4Conformance, ParseError> {
    let mut conformance = Ipv4Conformance::default();
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => {
                if options[offset + 1..].iter().any(|byte| *byte != 0) {
                    conformance.insert(Ipv4Conformance::NONZERO_OPTION_PADDING);
                }
                return Ok(conformance);
            }
            1 => offset += 1,
            _ => {
                let Some(&length) = options.get(offset + 1) else {
                    return Err(ParseError::Malformed {
                        layer: Layer::Ipv4,
                        field: Field::OptionLength,
                    });
                };
                let length = usize::from(length);
                if length < 2
                    || offset
                        .checked_add(length)
                        .is_none_or(|end| end > options.len())
                {
                    return Err(ParseError::Malformed {
                        layer: Layer::Ipv4,
                        field: Field::OptionLength,
                    });
                }
                offset += length;
            }
        }
    }
    Ok(conformance)
}
