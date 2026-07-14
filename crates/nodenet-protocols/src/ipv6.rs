use crate::{
    BuildError, Field, FragmentState, IpProtocol, Ipv6Address, Layer, MAX_IP_PACKET_LENGTH,
    MAX_IPV6_EXTENSION_BYTES, MAX_IPV6_EXTENSION_HEADER_COUNT, PacketKind, PacketLength,
    ParseError, ParseMode, Resource, UpperLayerState, network::classify_upper_layer,
};

const IPV6_HEADER_LENGTH: usize = 40;
const MAX_FRAGMENT_OFFSET: u16 = 0x1fff;
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const AUTHENTICATION: u8 = 51;
const DESTINATION_OPTIONS: u8 = 60;

/// A bounded IPv6 extension header used by the packet builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6Extension<'a> {
    HopByHopOptions {
        options: &'a [u8],
    },
    Routing {
        routing_type: u8,
        segments_left: u8,
        data: &'a [u8],
    },
    Fragment {
        offset_units: u16,
        more_fragments: bool,
        identification: u32,
    },
    DestinationOptions {
        options: &'a [u8],
    },
    Authentication {
        security_parameters_index: u32,
        sequence_number: u32,
        authentication_data: &'a [u8],
    },
}

impl Ipv6Extension<'_> {
    const fn protocol(self) -> IpProtocol {
        match self {
            Self::HopByHopOptions { .. } => IpProtocol::new(HOP_BY_HOP),
            Self::Routing { .. } => IpProtocol::new(ROUTING),
            Self::Fragment { .. } => IpProtocol::new(FRAGMENT),
            Self::DestinationOptions { .. } => IpProtocol::new(DESTINATION_OPTIONS),
            Self::Authentication { .. } => IpProtocol::new(AUTHENTICATION),
        }
    }

    fn encoded_length(self) -> Result<usize, BuildError> {
        let length = match self {
            Self::HopByHopOptions { options } | Self::DestinationOptions { options } => {
                if options.len() < 6
                    || !(options.len() + 2).is_multiple_of(8)
                    || !ipv6_options_are_valid(options)
                {
                    return Err(BuildError::InvalidValue {
                        field: Field::OptionLength,
                    });
                }
                options.len() + 2
            }
            Self::Routing { data, .. } => {
                let length = data
                    .len()
                    .checked_add(4)
                    .ok_or(BuildError::ArithmeticOverflow {
                        field: Field::ExtensionLength,
                    })?;
                if length < 8 || !length.is_multiple_of(8) {
                    return Err(BuildError::InvalidValue {
                        field: Field::ExtensionLength,
                    });
                }
                length
            }
            Self::Fragment { offset_units, .. } => {
                if offset_units > MAX_FRAGMENT_OFFSET {
                    return Err(BuildError::InvalidValue {
                        field: Field::FragmentOffset,
                    });
                }
                8
            }
            Self::Authentication {
                authentication_data,
                ..
            } => {
                let length = authentication_data.len().checked_add(12).ok_or(
                    BuildError::ArithmeticOverflow {
                        field: Field::ExtensionLength,
                    },
                )?;
                if !authentication_data.len().is_multiple_of(4) || length > 1_028 {
                    return Err(BuildError::InvalidValue {
                        field: Field::ExtensionLength,
                    });
                }
                length
            }
        };
        Ok(length)
    }
}

/// A canonical IPv6 packet builder with an explicit extension sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6Packet<'a> {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hop_limit: u8,
    pub source: Ipv6Address,
    pub destination: Ipv6Address,
    pub extensions: &'a [Ipv6Extension<'a>],
    pub upper_layer_protocol: IpProtocol,
    pub payload: &'a [u8],
}

impl Ipv6Packet<'_> {
    /// Returns the checked complete IPv6 packet length.
    ///
    /// # Errors
    ///
    /// Returns invalid extension/order/fragment fields, overflow, or a
    /// non-jumbogram payload ceiling error.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        let extension_bytes = self.validate()?;
        let payload_length = extension_bytes.checked_add(self.payload.len()).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::PayloadLength,
            },
        )?;
        let total = IPV6_HEADER_LENGTH.checked_add(payload_length).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            },
        )?;
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Encodes a canonical non-jumbogram IPv6 packet.
    ///
    /// # Errors
    ///
    /// Returns before modifying `output` if validation or capacity fails.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.required_length()?.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..required];
        encode_ipv6(self, encoded);
        Ok(encoded)
    }

    /// Builds an exactly sized owned IPv6 packet.
    ///
    /// # Errors
    ///
    /// Returns a validation error before allocation.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0; required];
        encode_ipv6(self, &mut output);
        Ok(output)
    }

    fn validate(&self) -> Result<usize, BuildError> {
        if self.flow_label > 0x000f_ffff {
            return Err(BuildError::InvalidValue {
                field: Field::FlowLabel,
            });
        }
        if self.extensions.len() > MAX_IPV6_EXTENSION_HEADER_COUNT {
            return Err(BuildError::InvalidValue {
                field: Field::ExtensionLength,
            });
        }
        let mut order = ExtensionOrder::default();
        let mut extension_bytes = 0_usize;
        let mut fragment_index = None;
        let mut fragment = None;
        for (index, extension) in self.extensions.iter().copied().enumerate() {
            order.observe(extension.protocol().get(), index);
            extension_bytes = extension_bytes
                .checked_add(extension.encoded_length()?)
                .ok_or(BuildError::ArithmeticOverflow {
                    field: Field::ExtensionLength,
                })?;
            if extension_bytes > MAX_IPV6_EXTENSION_BYTES {
                return Err(BuildError::InvalidValue {
                    field: Field::ExtensionLength,
                });
            }
            if let Ipv6Extension::Fragment {
                offset_units,
                more_fragments,
                ..
            } = extension
            {
                fragment_index = Some(index);
                fragment = Some((offset_units, more_fragments));
            }
        }
        if !order.issues.is_canonical() {
            return Err(BuildError::InvalidValue {
                field: Field::ExtensionOrder,
            });
        }
        if self.upper_layer_protocol.get() == 59 && !self.payload.is_empty() {
            return Err(BuildError::InvalidValue {
                field: Field::PayloadLength,
            });
        }
        if let (Some(index), Some((offset, more))) = (fragment_index, fragment) {
            if offset != 0 && index + 1 != self.extensions.len() {
                return Err(BuildError::InvalidValue {
                    field: Field::ExtensionOrder,
                });
            }
            if more {
                let before_fragment = self.extensions[..=index].iter().copied().try_fold(
                    0_usize,
                    |sum, extension| {
                        sum.checked_add(extension.encoded_length()?).ok_or(
                            BuildError::ArithmeticOverflow {
                                field: Field::ExtensionLength,
                            },
                        )
                    },
                )?;
                let fragmentable_length = extension_bytes
                    .checked_sub(before_fragment)
                    .and_then(|length| length.checked_add(self.payload.len()))
                    .ok_or(BuildError::ArithmeticOverflow {
                        field: Field::PayloadLength,
                    })?;
                if !fragmentable_length.is_multiple_of(8) {
                    return Err(BuildError::InvalidValue {
                        field: Field::PayloadLength,
                    });
                }
            }
        }
        let payload_length = extension_bytes.checked_add(self.payload.len()).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::PayloadLength,
            },
        )?;
        if payload_length > usize::from(u16::MAX) {
            return Err(BuildError::LengthExceedsLimit {
                actual: IPV6_HEADER_LENGTH + payload_length,
                maximum: IPV6_HEADER_LENGTH + usize::from(u16::MAX),
                kind: PacketKind::Ip,
            });
        }
        Ok(extension_bytes)
    }
}

/// One validated borrowed IPv6 extension header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedIpv6Extension<'a> {
    HopByHopOptions {
        options: &'a [u8],
    },
    Routing {
        routing_type: u8,
        segments_left: u8,
        data: &'a [u8],
    },
    Fragment {
        offset_units: u16,
        more_fragments: bool,
        identification: u32,
    },
    DestinationOptions {
        options: &'a [u8],
    },
    Authentication {
        security_parameters_index: u32,
        sequence_number: u32,
        authentication_data: &'a [u8],
    },
}

/// Fixed-capacity parsed extension collection with no input-driven allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIpv6Extensions<'a> {
    entries: [Option<ParsedIpv6Extension<'a>>; MAX_IPV6_EXTENSION_HEADER_COUNT],
    length: usize,
}

impl<'a> ParsedIpv6Extensions<'a> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<ParsedIpv6Extension<'a>> {
        self.entries.get(index).copied().flatten()
    }

    pub fn iter(&self) -> impl Iterator<Item = ParsedIpv6Extension<'a>> + '_ {
        self.entries[..self.length].iter().copied().flatten()
    }

    fn push(&mut self, extension: ParsedIpv6Extension<'a>) -> Result<(), ParseError> {
        if self.length == MAX_IPV6_EXTENSION_HEADER_COUNT {
            return Err(ParseError::LimitExceeded {
                resource: crate::Resource::Ipv6ExtensionHeaders,
                actual: self.length + 1,
                maximum: MAX_IPV6_EXTENSION_HEADER_COUNT,
            });
        }
        self.entries[self.length] = Some(extension);
        self.length += 1;
        Ok(())
    }
}

impl Default for ParsedIpv6Extensions<'_> {
    fn default() -> Self {
        Self {
            entries: [None; MAX_IPV6_EXTENSION_HEADER_COUNT],
            length: 0,
        }
    }
}

/// Non-fatal IPv6 extension-order observations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Ipv6Conformance(u16);

impl Ipv6Conformance {
    pub const HOP_BY_HOP_NOT_FIRST: Self = Self(1 << 0);
    pub const DUPLICATE_HOP_BY_HOP: Self = Self(1 << 1);
    pub const DUPLICATE_ROUTING: Self = Self(1 << 2);
    pub const DUPLICATE_FRAGMENT: Self = Self(1 << 3);
    pub const DUPLICATE_AUTHENTICATION: Self = Self(1 << 4);
    pub const TOO_MANY_DESTINATION_OPTIONS: Self = Self(1 << 5);
    pub const NON_CANONICAL_ORDER: Self = Self(1 << 6);
    pub const NO_NEXT_HEADER_DATA: Self = Self(1 << 7);

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

/// A validated borrowed IPv6 packet and its terminal upper-layer disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIpv6Packet<'a> {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub declared_payload_length: usize,
    pub first_next_header: IpProtocol,
    pub hop_limit: u8,
    pub source: Ipv6Address,
    pub destination: Ipv6Address,
    pub extensions: ParsedIpv6Extensions<'a>,
    pub extension_bytes: usize,
    pub fragment: FragmentState,
    pub upper_layer: UpperLayerState<'a>,
    pub trailing: &'a [u8],
    pub complete: bool,
    pub conformance: Ipv6Conformance,
}

/// Parses an IPv6 packet without reassembly or jumbogram support.
///
/// Compatible mode permits only a missing suffix after every present extension
/// has been validated. Truncated extensions remain hard errors.
///
/// # Errors
///
/// Returns structured base/extension length, count, order-independent content,
/// fragment-reserved-bit, jumbogram, or truncation errors.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded extension state machine is kept in wire order for auditability"
)]
pub fn parse_ipv6_packet(
    input: &[u8],
    mode: ParseMode,
) -> Result<ParsedIpv6Packet<'_>, ParseError> {
    if input.len() > MAX_IP_PACKET_LENGTH {
        return Err(ParseError::LimitExceeded {
            resource: Resource::IpPacketBytes,
            actual: input.len(),
            maximum: MAX_IP_PACKET_LENGTH,
        });
    }
    if input.len() < IPV6_HEADER_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Ipv6,
            required: IPV6_HEADER_LENGTH,
            actual: input.len(),
        });
    }
    if input[0] >> 4 != 6 {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv6,
            field: Field::Version,
        });
    }
    let declared_payload_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
    let first_next_header = IpProtocol::new(input[6]);
    if declared_payload_length == 0 && first_next_header.get() == HOP_BY_HOP {
        return Err(ParseError::Unsupported {
            layer: Layer::Ipv6,
            field: Field::PayloadLength,
        });
    }
    let declared_end = IPV6_HEADER_LENGTH + declared_payload_length;
    let complete = input.len() >= declared_end;
    if !complete && mode == ParseMode::Strict {
        return Err(ParseError::Truncated {
            layer: Layer::Ipv6,
            required: declared_end,
            actual: input.len(),
        });
    }
    let available_end = input.len().min(declared_end);
    let mut cursor = IPV6_HEADER_LENGTH;
    let mut next_header = first_next_header;
    let mut extensions = ParsedIpv6Extensions::default();
    let mut extension_bytes = 0_usize;
    let mut fragment = FragmentState::Unfragmented;
    let mut fragment_payload_start = None;
    let mut order = ExtensionOrder::default();

    while is_extension(next_header.get()) {
        if extensions.len() == MAX_IPV6_EXTENSION_HEADER_COUNT {
            return Err(ParseError::LimitExceeded {
                resource: crate::Resource::Ipv6ExtensionHeaders,
                actual: extensions.len() + 1,
                maximum: MAX_IPV6_EXTENSION_HEADER_COUNT,
            });
        }
        let extension_protocol = next_header.get();
        order.observe(extension_protocol, extensions.len());
        let remaining = input.get(cursor..available_end).unwrap_or_default();
        let (parsed, following, encoded_length) = parse_extension(extension_protocol, remaining)?;
        extension_bytes =
            extension_bytes
                .checked_add(encoded_length)
                .ok_or(ParseError::ArithmeticOverflow {
                    field: Field::ExtensionLength,
                })?;
        if extension_bytes > MAX_IPV6_EXTENSION_BYTES {
            return Err(ParseError::LimitExceeded {
                resource: crate::Resource::Ipv6ExtensionBytes,
                actual: extension_bytes,
                maximum: MAX_IPV6_EXTENSION_BYTES,
            });
        }
        extensions.push(parsed)?;
        cursor += encoded_length;
        next_header = following;

        if let ParsedIpv6Extension::Fragment {
            offset_units,
            more_fragments,
            ..
        } = parsed
        {
            fragment_payload_start = Some(cursor);
            fragment = if offset_units == 0 {
                FragmentState::First { more_fragments }
            } else {
                FragmentState::NonFirst {
                    offset_units,
                    more_fragments,
                }
            };
            if offset_units != 0 {
                break;
            }
        }
    }

    let payload = input.get(cursor..available_end).unwrap_or_default();
    let more_fragments = matches!(
        fragment,
        FragmentState::First {
            more_fragments: true
        } | FragmentState::NonFirst {
            more_fragments: true,
            ..
        }
    );
    if more_fragments
        && !fragment_payload_start
            .map_or(0, |start| declared_end - start)
            .is_multiple_of(8)
    {
        return Err(ParseError::Malformed {
            layer: Layer::Ipv6,
            field: Field::PayloadLength,
        });
    }
    let mut conformance = order.issues;
    let upper_layer = classify_upper_layer(next_header, payload, fragment, true);
    if matches!(upper_layer, UpperLayerState::NoNextHeader { trailing } if !trailing.is_empty()) {
        conformance.insert(Ipv6Conformance::NO_NEXT_HEADER_DATA);
    }
    let trailing = if complete {
        &input[declared_end..]
    } else {
        &[]
    };
    let version_traffic_flow = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    Ok(ParsedIpv6Packet {
        traffic_class: u8::try_from((version_traffic_flow >> 20) & 0xff).unwrap_or_default(),
        flow_label: version_traffic_flow & 0x000f_ffff,
        declared_payload_length,
        first_next_header,
        hop_limit: input[7],
        source: Ipv6Address::new(input[8..24].try_into().unwrap_or([0; 16])),
        destination: Ipv6Address::new(input[24..40].try_into().unwrap_or([0; 16])),
        extensions,
        extension_bytes,
        fragment,
        upper_layer,
        trailing,
        complete,
        conformance,
    })
}

fn parse_extension(
    protocol: u8,
    input: &[u8],
) -> Result<(ParsedIpv6Extension<'_>, IpProtocol, usize), ParseError> {
    let minimum = if protocol == FRAGMENT { 8 } else { 2 };
    require_extension_length(input, minimum)?;
    let following = IpProtocol::new(input[0]);
    match protocol {
        HOP_BY_HOP | DESTINATION_OPTIONS => {
            let length = (usize::from(input[1]) + 1) * 8;
            require_extension_length(input, length)?;
            let options = &input[2..length];
            if !ipv6_options_are_valid(options) {
                return Err(ParseError::Malformed {
                    layer: Layer::Ipv6Extension,
                    field: Field::OptionLength,
                });
            }
            let parsed = if protocol == HOP_BY_HOP {
                ParsedIpv6Extension::HopByHopOptions { options }
            } else {
                ParsedIpv6Extension::DestinationOptions { options }
            };
            Ok((parsed, following, length))
        }
        ROUTING => {
            let length = (usize::from(input[1]) + 1) * 8;
            require_extension_length(input, length.max(8))?;
            Ok((
                ParsedIpv6Extension::Routing {
                    routing_type: input[2],
                    segments_left: input[3],
                    data: &input[4..length],
                },
                following,
                length,
            ))
        }
        FRAGMENT => {
            let field = u16::from_be_bytes([input[2], input[3]]);
            if input[1] != 0 || field & 0x0006 != 0 {
                return Err(ParseError::Malformed {
                    layer: Layer::Ipv6Extension,
                    field: Field::Flags,
                });
            }
            Ok((
                ParsedIpv6Extension::Fragment {
                    offset_units: field >> 3,
                    more_fragments: field & 1 != 0,
                    identification: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                },
                following,
                8,
            ))
        }
        AUTHENTICATION => {
            let length = (usize::from(input[1]) + 2) * 4;
            if length < 12 {
                return Err(ParseError::Malformed {
                    layer: Layer::Ipv6Extension,
                    field: Field::ExtensionLength,
                });
            }
            require_extension_length(input, length)?;
            if input[2] != 0 || input[3] != 0 {
                return Err(ParseError::Malformed {
                    layer: Layer::Ipv6Extension,
                    field: Field::Flags,
                });
            }
            Ok((
                ParsedIpv6Extension::Authentication {
                    security_parameters_index: u32::from_be_bytes([
                        input[4], input[5], input[6], input[7],
                    ]),
                    sequence_number: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
                    authentication_data: &input[12..length],
                },
                following,
                length,
            ))
        }
        _ => unreachable!("caller checks extension protocol"),
    }
}

fn require_extension_length(input: &[u8], required: usize) -> Result<(), ParseError> {
    if input.len() < required {
        return Err(ParseError::Truncated {
            layer: Layer::Ipv6Extension,
            required,
            actual: input.len(),
        });
    }
    Ok(())
}

fn encode_ipv6(packet: Ipv6Packet<'_>, encoded: &mut [u8]) {
    let extension_bytes = packet
        .extensions
        .iter()
        .copied()
        .map(|extension| extension.encoded_length().unwrap_or_default())
        .sum::<usize>();
    let payload_length = extension_bytes + packet.payload.len();
    let first_word = (6_u32 << 28) | (u32::from(packet.traffic_class) << 20) | packet.flow_label;
    encoded[0..4].copy_from_slice(&first_word.to_be_bytes());
    encoded[4..6].copy_from_slice(
        &u16::try_from(payload_length)
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    let first_protocol = packet
        .extensions
        .first()
        .map_or(packet.upper_layer_protocol, |extension| {
            extension.protocol()
        });
    encoded[6] = first_protocol.get();
    encoded[7] = packet.hop_limit;
    encoded[8..24].copy_from_slice(&packet.source.octets());
    encoded[24..40].copy_from_slice(&packet.destination.octets());
    let mut offset = IPV6_HEADER_LENGTH;
    for (index, extension) in packet.extensions.iter().copied().enumerate() {
        let next = packet
            .extensions
            .get(index + 1)
            .map_or(packet.upper_layer_protocol, |following| {
                following.protocol()
            });
        let length = encode_extension(extension, next, &mut encoded[offset..]);
        offset += length;
    }
    encoded[offset..].copy_from_slice(packet.payload);
}

fn encode_extension(extension: Ipv6Extension<'_>, next: IpProtocol, output: &mut [u8]) -> usize {
    let length = extension.encoded_length().unwrap_or_default();
    output[0] = next.get();
    match extension {
        Ipv6Extension::HopByHopOptions { options }
        | Ipv6Extension::DestinationOptions { options } => {
            output[1] = u8::try_from(length / 8 - 1).unwrap_or_default();
            output[2..length].copy_from_slice(options);
        }
        Ipv6Extension::Routing {
            routing_type,
            segments_left,
            data,
        } => {
            output[1] = u8::try_from(length / 8 - 1).unwrap_or_default();
            output[2] = routing_type;
            output[3] = segments_left;
            output[4..length].copy_from_slice(data);
        }
        Ipv6Extension::Fragment {
            offset_units,
            more_fragments,
            identification,
        } => {
            output[1] = 0;
            let field = (offset_units << 3) | u16::from(more_fragments);
            output[2..4].copy_from_slice(&field.to_be_bytes());
            output[4..8].copy_from_slice(&identification.to_be_bytes());
        }
        Ipv6Extension::Authentication {
            security_parameters_index,
            sequence_number,
            authentication_data,
        } => {
            output[1] = u8::try_from(length / 4 - 2).unwrap_or_default();
            output[2..4].fill(0);
            output[4..8].copy_from_slice(&security_parameters_index.to_be_bytes());
            output[8..12].copy_from_slice(&sequence_number.to_be_bytes());
            output[12..length].copy_from_slice(authentication_data);
        }
    }
    length
}

fn ipv6_options_are_valid(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        if options[offset] == 0 {
            offset += 1;
            continue;
        }
        let Some(&length) = options.get(offset + 1) else {
            return false;
        };
        let Some(end) = offset.checked_add(2 + usize::from(length)) else {
            return false;
        };
        if end > options.len() {
            return false;
        }
        offset = end;
    }
    true
}

const fn is_extension(protocol: u8) -> bool {
    matches!(
        protocol,
        HOP_BY_HOP | ROUTING | FRAGMENT | AUTHENTICATION | DESTINATION_OPTIONS
    )
}

#[derive(Default)]
struct ExtensionOrder {
    issues: Ipv6Conformance,
    stage: u8,
    hop_by_hop: u8,
    routing: u8,
    fragment: u8,
    authentication: u8,
    destination_options: u8,
}

impl ExtensionOrder {
    fn observe(&mut self, protocol: u8, index: usize) {
        match protocol {
            HOP_BY_HOP => {
                self.hop_by_hop += 1;
                if index != 0 {
                    self.issues.insert(Ipv6Conformance::HOP_BY_HOP_NOT_FIRST);
                }
                if self.hop_by_hop > 1 {
                    self.issues.insert(Ipv6Conformance::DUPLICATE_HOP_BY_HOP);
                }
                if self.stage != 0 {
                    self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                }
            }
            DESTINATION_OPTIONS => {
                self.destination_options += 1;
                if self.destination_options > 2 {
                    self.issues
                        .insert(Ipv6Conformance::TOO_MANY_DESTINATION_OPTIONS);
                }
                if self.destination_options == 1 {
                    self.stage = if self.stage <= 1 { 1 } else { 5 };
                } else {
                    if self.routing == 0 {
                        self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                    }
                    self.stage = 5;
                }
            }
            ROUTING => {
                self.routing += 1;
                if self.routing > 1 {
                    self.issues.insert(Ipv6Conformance::DUPLICATE_ROUTING);
                }
                if self.stage > 1 {
                    self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                }
                self.stage = self.stage.max(2);
            }
            FRAGMENT => {
                self.fragment += 1;
                if self.fragment > 1 {
                    self.issues.insert(Ipv6Conformance::DUPLICATE_FRAGMENT);
                }
                if self.destination_options > 0 && self.routing == 0 {
                    self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                }
                if self.stage > 2 {
                    self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                }
                self.stage = self.stage.max(3);
            }
            AUTHENTICATION => {
                self.authentication += 1;
                if self.authentication > 1 {
                    self.issues
                        .insert(Ipv6Conformance::DUPLICATE_AUTHENTICATION);
                }
                if self.destination_options > 0 && self.routing == 0 {
                    self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                }
                if self.stage > 3 {
                    self.issues.insert(Ipv6Conformance::NON_CANONICAL_ORDER);
                }
                self.stage = self.stage.max(4);
            }
            _ => {}
        }
    }
}
