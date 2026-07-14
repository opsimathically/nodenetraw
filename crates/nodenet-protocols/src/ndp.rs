use crate::{
    BuildError, Field, IpProtocol, Ipv6Address, Layer, MAX_ICMPV6_MESSAGE_BYTES,
    MAX_NDP_OPTION_BYTES, MAX_NDP_OPTION_COUNT, PacketKind, PacketLength, ParseError, Resource,
    TransportChecksumContext, compute_transport_checksum, validate_transport_checksum,
};

const ICMPV6_PROTOCOL: IpProtocol = IpProtocol::new(58);
const ALL_NODES: Ipv6Address =
    Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const ALL_ROUTERS: Ipv6Address =
    Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

/// IPv6 addressing metadata required to validate an NDP message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NdpContext {
    pub source: Ipv6Address,
    pub destination: Ipv6Address,
    pub hop_limit: u8,
}

impl NdpContext {
    const fn checksum_context(self) -> TransportChecksumContext {
        TransportChecksumContext::Ipv6 {
            source: self.source,
            destination: self.destination,
        }
    }
}

/// A canonical RFC 4861 Neighbor Discovery message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NdpMessage {
    RouterSolicitation,
    RouterAdvertisement {
        current_hop_limit: u8,
        managed: bool,
        other_configuration: bool,
        preference: i8,
        router_lifetime: u16,
        reachable_time: u32,
        retransmit_timer: u32,
    },
    NeighborSolicitation {
        target: Ipv6Address,
    },
    NeighborAdvertisement {
        router: bool,
        solicited: bool,
        override_flag: bool,
        target: Ipv6Address,
    },
    Redirect {
        target: Ipv6Address,
        destination: Ipv6Address,
    },
}

/// A bounded, canonical NDP option accepted by the builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NdpOption<'a> {
    SourceLinkLayerAddress([u8; 6]),
    TargetLinkLayerAddress([u8; 6]),
    PrefixInformation {
        prefix_length: u8,
        on_link: bool,
        autonomous: bool,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Address,
    },
    RedirectedHeader(&'a [u8]),
    Mtu(u32),
    Unknown {
        kind: u8,
        body: &'a [u8],
    },
}

impl NdpOption<'_> {
    fn required_length(self) -> Result<usize, BuildError> {
        let length = match self {
            Self::SourceLinkLayerAddress(_) | Self::TargetLinkLayerAddress(_) | Self::Mtu(_) => 8,
            Self::PrefixInformation { .. } => 32,
            Self::RedirectedHeader(quote) => rounded_option_length(8, quote.len())?,
            Self::Unknown { kind, body } => {
                if matches!(kind, 0..=5) {
                    return Err(BuildError::InvalidValue {
                        field: Field::OptionKind,
                    });
                }
                rounded_option_length(2, body.len())?
            }
        };
        if length > usize::from(u8::MAX) * 8 {
            return Err(BuildError::LengthExceedsLimit {
                actual: length,
                maximum: usize::from(u8::MAX) * 8,
                kind: PacketKind::Ip,
            });
        }
        Ok(length)
    }
}

/// A complete NDP builder with packet-context validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NdpPacket<'a> {
    pub context: NdpContext,
    pub message: NdpMessage,
    pub options: &'a [NdpOption<'a>],
}

impl NdpPacket<'_> {
    /// Returns the checked wire length after validating all RFC invariants.
    ///
    /// # Errors
    ///
    /// Rejects invalid addressing, flags, options, limits, and arithmetic.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        validate_context(self.context, self.message, self.options)?;
        if self.options.len() > MAX_NDP_OPTION_COUNT {
            return Err(BuildError::LengthExceedsLimit {
                actual: self.options.len(),
                maximum: MAX_NDP_OPTION_COUNT,
                kind: PacketKind::Ip,
            });
        }
        let mut option_bytes = 0_usize;
        for option in self.options {
            option_bytes = option_bytes.checked_add(option.required_length()?).ok_or(
                BuildError::ArithmeticOverflow {
                    field: Field::OptionLength,
                },
            )?;
        }
        if option_bytes > MAX_NDP_OPTION_BYTES {
            return Err(BuildError::LengthExceedsLimit {
                actual: option_bytes,
                maximum: MAX_NDP_OPTION_BYTES,
                kind: PacketKind::Ip,
            });
        }
        let total = message_length(self.message)
            .checked_add(option_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            })?;
        if total > MAX_ICMPV6_MESSAGE_BYTES {
            return Err(BuildError::LengthExceedsLimit {
                actual: total,
                maximum: MAX_ICMPV6_MESSAGE_BYTES,
                kind: PacketKind::Ip,
            });
        }
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Writes a checksum-complete message transactionally.
    ///
    /// # Errors
    ///
    /// Returns without output mutation if validation or capacity fails.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.required_length()?.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..required];
        encoded.fill(0);
        write_message(self.message, encoded);
        let mut offset = message_length(self.message);
        for option in self.options {
            let length = option.required_length()?;
            write_option(*option, &mut encoded[offset..offset + length]);
            offset += length;
        }
        let checksum =
            compute_transport_checksum(self.context.checksum_context(), ICMPV6_PROTOCOL, encoded)
                .ok_or(BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            })?;
        encoded[2..4].copy_from_slice(&checksum.to_be_bytes());
        Ok(encoded)
    }

    /// Builds an exactly sized NDP message.
    ///
    /// # Errors
    ///
    /// Returns validation and length errors before exposing output.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0_u8; required];
        self.write_into(&mut output)?;
        Ok(output)
    }
}

/// Non-fatal compatibility observations on a parsed NDP packet.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NdpConformance(u16);

impl NdpConformance {
    pub const RESERVED_FIELD_NONZERO: Self = Self(1 << 0);
    pub const RESERVED_PREFERENCE: Self = Self(1 << 1);
    pub const DUPLICATE_SINGLETON_OPTION: Self = Self(1 << 2);
    pub const OPTION_NOT_ALLOWED: Self = Self(1 << 3);
    pub const PREFERRED_LIFETIME_EXCEEDS_VALID: Self = Self(1 << 4);

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

/// A zero-copy parsed NDP option. Unknown options remain available verbatim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedNdpOption<'a> {
    SourceLinkLayerAddress(&'a [u8]),
    TargetLinkLayerAddress(&'a [u8]),
    PrefixInformation {
        prefix_length: u8,
        flags: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Address,
    },
    RedirectedHeader {
        quote: &'a [u8],
    },
    Mtu(u32),
    Unknown {
        kind: u8,
        body: &'a [u8],
    },
}

/// Fixed-capacity parsed option storage with no input-directed allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedNdpOptions<'a> {
    entries: [Option<ParsedNdpOption<'a>>; MAX_NDP_OPTION_COUNT],
    length: usize,
}

impl<'a> ParsedNdpOptions<'a> {
    pub fn iter(&self) -> impl Iterator<Item = ParsedNdpOption<'a>> + '_ {
        self.entries[..self.length].iter().copied().flatten()
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// A parsed NDP message with decoded fixed fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedNdpMessage {
    RouterSolicitation,
    RouterAdvertisement {
        current_hop_limit: u8,
        managed: bool,
        other_configuration: bool,
        preference: i8,
        router_lifetime: u16,
        reachable_time: u32,
        retransmit_timer: u32,
    },
    NeighborSolicitation {
        target: Ipv6Address,
    },
    NeighborAdvertisement {
        router: bool,
        solicited: bool,
        override_flag: bool,
        target: Ipv6Address,
    },
    Redirect {
        target: Ipv6Address,
        destination: Ipv6Address,
    },
}

/// A fully validated, checksum-verified NDP packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedNdpPacket<'a> {
    pub checksum: u16,
    pub message: ParsedNdpMessage,
    pub options: ParsedNdpOptions<'a>,
    pub conformance: NdpConformance,
}

/// Parses and validates one complete NDP message.
///
/// # Errors
///
/// Rejects bad checksums, code, hop limit, fixed lengths, option units, and
/// invalid source, destination, or target addressing.
#[allow(
    clippy::too_many_lines,
    reason = "fixed-field dispatch stays adjacent to its wire validation"
)]
pub fn parse_ndp_message(
    input: &[u8],
    context: NdpContext,
) -> Result<ParsedNdpPacket<'_>, ParseError> {
    if input.len() > MAX_ICMPV6_MESSAGE_BYTES {
        return Err(ParseError::LimitExceeded {
            resource: Resource::TransportBytes,
            actual: input.len(),
            maximum: MAX_ICMPV6_MESSAGE_BYTES,
        });
    }
    if context.hop_limit != u8::MAX {
        return Err(ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::HeaderLength,
        });
    }
    if input.len() < 8 {
        return Err(ParseError::Truncated {
            layer: Layer::Ndp,
            required: 8,
            actual: input.len(),
        });
    }
    if input[1] != 0 {
        return Err(ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::Code,
        });
    }
    if !validate_transport_checksum(context.checksum_context(), ICMPV6_PROTOCOL, input) {
        return Err(ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::Checksum,
        });
    }
    let mut conformance = NdpConformance::default();
    let (message, option_offset) = match input[0] {
        133 => {
            require_length(input, 8)?;
            mark_reserved(&mut conformance, &input[4..8]);
            (ParsedNdpMessage::RouterSolicitation, 8)
        }
        134 => {
            require_length(input, 16)?;
            let flags = input[5];
            let preference = decode_preference((flags >> 3) & 0x03);
            if preference.is_none() {
                conformance.insert(NdpConformance::RESERVED_PREFERENCE);
            }
            if flags & 0x27 != 0 {
                conformance.insert(NdpConformance::RESERVED_FIELD_NONZERO);
            }
            (
                ParsedNdpMessage::RouterAdvertisement {
                    current_hop_limit: input[4],
                    managed: flags & 0x80 != 0,
                    other_configuration: flags & 0x40 != 0,
                    preference: preference.unwrap_or(0),
                    router_lifetime: read_u16(input, 6),
                    reachable_time: read_u32(input, 8),
                    retransmit_timer: read_u32(input, 12),
                },
                16,
            )
        }
        135 => {
            require_length(input, 24)?;
            mark_reserved(&mut conformance, &input[4..8]);
            (
                ParsedNdpMessage::NeighborSolicitation {
                    target: read_address(input, 8),
                },
                24,
            )
        }
        136 => {
            require_length(input, 24)?;
            let flags = input[4];
            if flags & 0x1f != 0 || input[5..8].iter().any(|byte| *byte != 0) {
                conformance.insert(NdpConformance::RESERVED_FIELD_NONZERO);
            }
            (
                ParsedNdpMessage::NeighborAdvertisement {
                    router: flags & 0x80 != 0,
                    solicited: flags & 0x40 != 0,
                    override_flag: flags & 0x20 != 0,
                    target: read_address(input, 8),
                },
                24,
            )
        }
        137 => {
            require_length(input, 40)?;
            mark_reserved(&mut conformance, &input[4..8]);
            (
                ParsedNdpMessage::Redirect {
                    target: read_address(input, 8),
                    destination: read_address(input, 24),
                },
                40,
            )
        }
        _ => {
            return Err(ParseError::Malformed {
                layer: Layer::Ndp,
                field: Field::Type,
            });
        }
    };
    let options = parse_options(&input[option_offset..], &mut conformance)?;
    validate_parsed_context(context, message, &options, &mut conformance)?;
    Ok(ParsedNdpPacket {
        checksum: read_u16(input, 2),
        message,
        options,
        conformance,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded option decoder keeps each wire format beside its length check"
)]
fn parse_options<'a>(
    input: &'a [u8],
    conformance: &mut NdpConformance,
) -> Result<ParsedNdpOptions<'a>, ParseError> {
    if input.len() > MAX_NDP_OPTION_BYTES {
        return Err(ParseError::LimitExceeded {
            resource: Resource::NdpOptionBytes,
            actual: input.len(),
            maximum: MAX_NDP_OPTION_BYTES,
        });
    }
    let mut options = ParsedNdpOptions {
        entries: [None; MAX_NDP_OPTION_COUNT],
        length: 0,
    };
    let mut offset = 0_usize;
    while offset < input.len() {
        if input.len() - offset < 2 {
            return Err(ParseError::Truncated {
                layer: Layer::Ndp,
                required: offset + 2,
                actual: input.len(),
            });
        }
        let units = usize::from(input[offset + 1]);
        if units == 0 {
            return Err(ParseError::Malformed {
                layer: Layer::Ndp,
                field: Field::OptionLength,
            });
        }
        let length = units * 8;
        let end = offset
            .checked_add(length)
            .ok_or(ParseError::ArithmeticOverflow {
                field: Field::OptionLength,
            })?;
        if end > input.len() {
            return Err(ParseError::Truncated {
                layer: Layer::Ndp,
                required: end,
                actual: input.len(),
            });
        }
        if options.length == MAX_NDP_OPTION_COUNT {
            return Err(ParseError::LimitExceeded {
                resource: Resource::NdpOptions,
                actual: options.length + 1,
                maximum: MAX_NDP_OPTION_COUNT,
            });
        }
        let kind = input[offset];
        let body = &input[offset + 2..end];
        let option = match (kind, length) {
            (1, _) => ParsedNdpOption::SourceLinkLayerAddress(body),
            (2, _) => ParsedNdpOption::TargetLinkLayerAddress(body),
            (3, 32) => {
                let preferred = read_u32(input, offset + 8);
                let valid = read_u32(input, offset + 4);
                if preferred > valid {
                    conformance.insert(NdpConformance::PREFERRED_LIFETIME_EXCEEDS_VALID);
                }
                if input[offset + 12..offset + 16]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    conformance.insert(NdpConformance::RESERVED_FIELD_NONZERO);
                }
                ParsedNdpOption::PrefixInformation {
                    prefix_length: input[offset + 2],
                    flags: input[offset + 3],
                    valid_lifetime: valid,
                    preferred_lifetime: preferred,
                    prefix: read_address(input, offset + 16),
                }
            }
            (4, length) if length >= 8 => {
                if input[offset + 2..offset + 8].iter().any(|byte| *byte != 0) {
                    conformance.insert(NdpConformance::RESERVED_FIELD_NONZERO);
                }
                ParsedNdpOption::RedirectedHeader {
                    quote: &input[offset + 8..end],
                }
            }
            (5, 8) => {
                if input[offset + 2..offset + 4].iter().any(|byte| *byte != 0) {
                    conformance.insert(NdpConformance::RESERVED_FIELD_NONZERO);
                }
                ParsedNdpOption::Mtu(read_u32(input, offset + 4))
            }
            (3..=5, _) => {
                return Err(ParseError::Malformed {
                    layer: Layer::Ndp,
                    field: Field::OptionLength,
                });
            }
            _ => ParsedNdpOption::Unknown { kind, body },
        };
        options.entries[options.length] = Some(option);
        options.length += 1;
        offset = end;
    }
    Ok(options)
}

fn validate_context(
    context: NdpContext,
    message: NdpMessage,
    options: &[NdpOption<'_>],
) -> Result<(), BuildError> {
    if context.hop_limit != u8::MAX {
        return Err(BuildError::InvalidValue {
            field: Field::HeaderLength,
        });
    }
    validate_option_placement(message, options)?;
    match message {
        NdpMessage::RouterSolicitation => {
            if context.destination != ALL_ROUTERS
                || (!is_unspecified(context.source) && is_multicast(context.source))
                || (is_unspecified(context.source)
                    && options
                        .iter()
                        .any(|option| matches!(option, NdpOption::SourceLinkLayerAddress(_))))
            {
                return invalid_address();
            }
        }
        NdpMessage::RouterAdvertisement { preference, .. } => {
            if !matches!(preference, -1..=1)
                || !is_link_local(context.source)
                || is_unspecified(context.destination)
                || (is_multicast(context.destination) && context.destination != ALL_NODES)
            {
                return invalid_address();
            }
        }
        NdpMessage::NeighborSolicitation { target } => {
            if invalid_target(target) {
                return invalid_address();
            }
            if is_unspecified(context.source) {
                if context.destination != solicited_node_multicast(target)
                    || options
                        .iter()
                        .any(|option| matches!(option, NdpOption::SourceLinkLayerAddress(_)))
                {
                    return invalid_address();
                }
            } else if is_multicast(context.source)
                || (context.destination != target
                    && context.destination != solicited_node_multicast(target))
            {
                return invalid_address();
            }
        }
        NdpMessage::NeighborAdvertisement {
            solicited, target, ..
        } => {
            if invalid_target(target)
                || is_unspecified(context.source)
                || is_multicast(context.source)
                || is_unspecified(context.destination)
                || (is_multicast(context.destination) && solicited)
            {
                return invalid_address();
            }
        }
        NdpMessage::Redirect {
            target,
            destination,
        } => {
            if !is_link_local(context.source)
                || is_unspecified(context.destination)
                || is_multicast(context.destination)
                || invalid_target(destination)
                || !(is_link_local(target) || target == destination)
            {
                return invalid_address();
            }
        }
    }
    Ok(())
}

fn validate_parsed_context(
    context: NdpContext,
    message: ParsedNdpMessage,
    options: &ParsedNdpOptions<'_>,
    conformance: &mut NdpConformance,
) -> Result<(), ParseError> {
    let mut source_lla = 0_usize;
    let mut target_lla = 0_usize;
    let mut mtu = 0_usize;
    for option in options.iter() {
        match option {
            ParsedNdpOption::SourceLinkLayerAddress(_) => source_lla += 1,
            ParsedNdpOption::TargetLinkLayerAddress(_) => target_lla += 1,
            ParsedNdpOption::Mtu(_) => mtu += 1,
            _ => {}
        }
        if !parsed_option_allowed(message, option) {
            conformance.insert(NdpConformance::OPTION_NOT_ALLOWED);
        }
    }
    if source_lla > 1 || target_lla > 1 || mtu > 1 {
        conformance.insert(NdpConformance::DUPLICATE_SINGLETON_OPTION);
    }
    let builder_message = match message {
        ParsedNdpMessage::RouterSolicitation => NdpMessage::RouterSolicitation,
        ParsedNdpMessage::RouterAdvertisement {
            current_hop_limit,
            managed,
            other_configuration,
            preference,
            router_lifetime,
            reachable_time,
            retransmit_timer,
        } => NdpMessage::RouterAdvertisement {
            current_hop_limit,
            managed,
            other_configuration,
            preference,
            router_lifetime,
            reachable_time,
            retransmit_timer,
        },
        ParsedNdpMessage::NeighborSolicitation { target } => {
            NdpMessage::NeighborSolicitation { target }
        }
        ParsedNdpMessage::NeighborAdvertisement {
            router,
            solicited,
            override_flag,
            target,
        } => NdpMessage::NeighborAdvertisement {
            router,
            solicited,
            override_flag,
            target,
        },
        ParsedNdpMessage::Redirect {
            target,
            destination,
        } => NdpMessage::Redirect {
            target,
            destination,
        },
    };
    validate_context_without_options(context, builder_message).map_err(|_| {
        ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::Address,
        }
    })?;
    if matches!(message, ParsedNdpMessage::RouterSolicitation)
        && is_unspecified(context.source)
        && source_lla != 0
    {
        return Err(ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::Address,
        });
    }
    Ok(())
}

fn validate_context_without_options(
    context: NdpContext,
    message: NdpMessage,
) -> Result<(), BuildError> {
    validate_context(context, message, &[])
}

fn validate_option_placement(
    message: NdpMessage,
    options: &[NdpOption<'_>],
) -> Result<(), BuildError> {
    let mut source_lla = 0_usize;
    let mut target_lla = 0_usize;
    let mut mtu = 0_usize;
    for option in options {
        let allowed = matches!(
            (message, option),
            (
                NdpMessage::RouterSolicitation
                    | NdpMessage::RouterAdvertisement { .. }
                    | NdpMessage::NeighborSolicitation { .. },
                NdpOption::SourceLinkLayerAddress(_),
            ) | (
                NdpMessage::NeighborAdvertisement { .. } | NdpMessage::Redirect { .. },
                NdpOption::TargetLinkLayerAddress(_),
            ) | (
                NdpMessage::RouterAdvertisement { .. },
                NdpOption::PrefixInformation { .. } | NdpOption::Mtu(_),
            ) | (NdpMessage::Redirect { .. }, NdpOption::RedirectedHeader(_))
                | (_, NdpOption::Unknown { .. })
        );
        if !allowed {
            return Err(BuildError::InvalidValue {
                field: Field::OptionKind,
            });
        }
        match option {
            NdpOption::SourceLinkLayerAddress(_) => source_lla += 1,
            NdpOption::TargetLinkLayerAddress(_) => target_lla += 1,
            NdpOption::Mtu(_) => mtu += 1,
            NdpOption::PrefixInformation {
                valid_lifetime,
                preferred_lifetime,
                ..
            } if preferred_lifetime > valid_lifetime => {
                return Err(BuildError::InvalidValue {
                    field: Field::OptionLength,
                });
            }
            _ => {}
        }
    }
    if source_lla > 1 || target_lla > 1 || mtu > 1 {
        return Err(BuildError::InvalidValue {
            field: Field::OptionKind,
        });
    }
    Ok(())
}

fn parsed_option_allowed(message: ParsedNdpMessage, option: ParsedNdpOption<'_>) -> bool {
    matches!(
        (message, option),
        (
            ParsedNdpMessage::RouterSolicitation
                | ParsedNdpMessage::RouterAdvertisement { .. }
                | ParsedNdpMessage::NeighborSolicitation { .. },
            ParsedNdpOption::SourceLinkLayerAddress(_)
        ) | (
            ParsedNdpMessage::NeighborAdvertisement { .. } | ParsedNdpMessage::Redirect { .. },
            ParsedNdpOption::TargetLinkLayerAddress(_)
        ) | (
            ParsedNdpMessage::RouterAdvertisement { .. },
            ParsedNdpOption::PrefixInformation { .. } | ParsedNdpOption::Mtu(_)
        ) | (
            ParsedNdpMessage::Redirect { .. },
            ParsedNdpOption::RedirectedHeader { .. }
        ) | (_, ParsedNdpOption::Unknown { .. })
    )
}

const fn message_length(message: NdpMessage) -> usize {
    match message {
        NdpMessage::RouterSolicitation => 8,
        NdpMessage::RouterAdvertisement { .. } => 16,
        NdpMessage::NeighborSolicitation { .. } | NdpMessage::NeighborAdvertisement { .. } => 24,
        NdpMessage::Redirect { .. } => 40,
    }
}

fn write_message(message: NdpMessage, output: &mut [u8]) {
    match message {
        NdpMessage::RouterSolicitation => output[0] = 133,
        NdpMessage::RouterAdvertisement {
            current_hop_limit,
            managed,
            other_configuration,
            preference,
            router_lifetime,
            reachable_time,
            retransmit_timer,
        } => {
            output[0] = 134;
            output[4] = current_hop_limit;
            output[5] = u8::from(managed) << 7
                | u8::from(other_configuration) << 6
                | encode_preference(preference) << 3;
            output[6..8].copy_from_slice(&router_lifetime.to_be_bytes());
            output[8..12].copy_from_slice(&reachable_time.to_be_bytes());
            output[12..16].copy_from_slice(&retransmit_timer.to_be_bytes());
        }
        NdpMessage::NeighborSolicitation { target } => {
            output[0] = 135;
            output[8..24].copy_from_slice(&target.octets());
        }
        NdpMessage::NeighborAdvertisement {
            router,
            solicited,
            override_flag,
            target,
        } => {
            output[0] = 136;
            output[4] =
                u8::from(router) << 7 | u8::from(solicited) << 6 | u8::from(override_flag) << 5;
            output[8..24].copy_from_slice(&target.octets());
        }
        NdpMessage::Redirect {
            target,
            destination,
        } => {
            output[0] = 137;
            output[8..24].copy_from_slice(&target.octets());
            output[24..40].copy_from_slice(&destination.octets());
        }
    }
}

fn write_option(option: NdpOption<'_>, output: &mut [u8]) {
    output.fill(0);
    output[1] = u8::try_from(output.len() / 8).expect("validated NDP option unit count");
    match option {
        NdpOption::SourceLinkLayerAddress(address) => {
            output[0] = 1;
            output[2..8].copy_from_slice(&address);
        }
        NdpOption::TargetLinkLayerAddress(address) => {
            output[0] = 2;
            output[2..8].copy_from_slice(&address);
        }
        NdpOption::PrefixInformation {
            prefix_length,
            on_link,
            autonomous,
            valid_lifetime,
            preferred_lifetime,
            prefix,
        } => {
            output[0] = 3;
            output[2] = prefix_length;
            output[3] = u8::from(on_link) << 7 | u8::from(autonomous) << 6;
            output[4..8].copy_from_slice(&valid_lifetime.to_be_bytes());
            output[8..12].copy_from_slice(&preferred_lifetime.to_be_bytes());
            output[16..32].copy_from_slice(&prefix.octets());
        }
        NdpOption::RedirectedHeader(quote) => {
            output[0] = 4;
            output[8..8 + quote.len()].copy_from_slice(quote);
        }
        NdpOption::Mtu(mtu) => {
            output[0] = 5;
            output[4..8].copy_from_slice(&mtu.to_be_bytes());
        }
        NdpOption::Unknown { kind, body } => {
            output[0] = kind;
            output[2..2 + body.len()].copy_from_slice(body);
        }
    }
}

fn rounded_option_length(header: usize, body: usize) -> Result<usize, BuildError> {
    header
        .checked_add(body)
        .and_then(|length| length.checked_add(7))
        .map(|length| length / 8 * 8)
        .ok_or(BuildError::ArithmeticOverflow {
            field: Field::OptionLength,
        })
}

fn require_length(input: &[u8], required: usize) -> Result<(), ParseError> {
    if input.len() < required {
        return Err(ParseError::Truncated {
            layer: Layer::Ndp,
            required,
            actual: input.len(),
        });
    }
    Ok(())
}

fn mark_reserved(conformance: &mut NdpConformance, input: &[u8]) {
    if input.iter().any(|byte| *byte != 0) {
        conformance.insert(NdpConformance::RESERVED_FIELD_NONZERO);
    }
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_address(input: &[u8], offset: usize) -> Ipv6Address {
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&input[offset..offset + 16]);
    Ipv6Address::new(octets)
}

const fn encode_preference(preference: i8) -> u8 {
    match preference {
        1 => 1,
        -1 => 3,
        _ => 0,
    }
}

const fn decode_preference(encoded: u8) -> Option<i8> {
    match encoded {
        0 => Some(0),
        1 => Some(1),
        3 => Some(-1),
        _ => None,
    }
}

fn invalid_address<T>() -> Result<T, BuildError> {
    Err(BuildError::InvalidValue {
        field: Field::Address,
    })
}

fn is_unspecified(address: Ipv6Address) -> bool {
    address.octets() == [0; 16]
}

const fn is_multicast(address: Ipv6Address) -> bool {
    address.octets()[0] == 0xff
}

const fn is_link_local(address: Ipv6Address) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

fn invalid_target(address: Ipv6Address) -> bool {
    is_unspecified(address) || is_multicast(address)
}

const fn solicited_node_multicast(target: Ipv6Address) -> Ipv6Address {
    let target = target.octets();
    Ipv6Address::new([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, target[13], target[14], target[15],
    ])
}
