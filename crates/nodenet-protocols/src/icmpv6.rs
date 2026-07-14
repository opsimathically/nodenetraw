use crate::{
    BuildError, Field, IpAddress, IpProtocol, Layer, MAX_ICMPV6_MESSAGE_BYTES, PacketKind,
    PacketLength, ParseError, QuotedIpPacket, Resource, TransportChecksumContext,
    compute_transport_checksum, parse_quoted_ip_packet, validate_transport_checksum,
};

const ICMPV6_HEADER_LENGTH: usize = 8;
const ICMPV6_PROTOCOL: IpProtocol = IpProtocol::new(58);

/// A canonical scanner-relevant `ICMPv6` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv6Message<'a> {
    EchoRequest {
        identifier: u16,
        sequence: u16,
        payload: &'a [u8],
    },
    EchoReply {
        identifier: u16,
        sequence: u16,
        payload: &'a [u8],
    },
    DestinationUnreachable {
        code: u8,
        quote: &'a [u8],
    },
    PacketTooBig {
        mtu: u32,
        quote: &'a [u8],
    },
    TimeExceeded {
        code: u8,
        quote: &'a [u8],
    },
    ParameterProblem {
        code: u8,
        pointer: u32,
        quote: &'a [u8],
    },
}

/// An `ICMPv6` builder bound to its IPv6 pseudo-header addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Icmpv6Packet<'a> {
    pub checksum_context: TransportChecksumContext,
    pub message: Icmpv6Message<'a>,
}

impl Icmpv6Packet<'_> {
    /// Returns the checked encoded message length.
    ///
    /// # Errors
    ///
    /// Rejects non-IPv6 contexts, unsupported codes, invalid quotes, and size
    /// overflow.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        if !matches!(self.checksum_context, TransportChecksumContext::Ipv6 { .. }) {
            return Err(BuildError::InvalidValue {
                field: Field::Address,
            });
        }
        let variable_length = match self.message {
            Icmpv6Message::EchoRequest { payload, .. }
            | Icmpv6Message::EchoReply { payload, .. } => payload.len(),
            Icmpv6Message::DestinationUnreachable { code, quote } => {
                if code > 7 {
                    return Err(BuildError::InvalidValue { field: Field::Code });
                }
                validate_error_quote_v6(quote)?;
                quote.len()
            }
            Icmpv6Message::PacketTooBig { quote, .. } => {
                validate_error_quote_v6(quote)?;
                quote.len()
            }
            Icmpv6Message::TimeExceeded { code, quote } => {
                if code > 1 {
                    return Err(BuildError::InvalidValue { field: Field::Code });
                }
                validate_error_quote_v6(quote)?;
                quote.len()
            }
            Icmpv6Message::ParameterProblem { code, quote, .. } => {
                if code > 2 {
                    return Err(BuildError::InvalidValue { field: Field::Code });
                }
                validate_error_quote_v6(quote)?;
                quote.len()
            }
        };
        let total = ICMPV6_HEADER_LENGTH.checked_add(variable_length).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            },
        )?;
        if total > MAX_ICMPV6_MESSAGE_BYTES {
            return Err(BuildError::LengthExceedsLimit {
                actual: total,
                maximum: MAX_ICMPV6_MESSAGE_BYTES,
                kind: PacketKind::Ip,
            });
        }
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Writes a checksum-complete `ICMPv6` message transactionally.
    ///
    /// # Errors
    ///
    /// Returns before output mutation on validation or capacity failure.
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
        match self.message {
            Icmpv6Message::EchoRequest {
                identifier,
                sequence,
                payload,
            }
            | Icmpv6Message::EchoReply {
                identifier,
                sequence,
                payload,
            } => {
                encoded[0] = if matches!(self.message, Icmpv6Message::EchoRequest { .. }) {
                    128
                } else {
                    129
                };
                encoded[4..6].copy_from_slice(&identifier.to_be_bytes());
                encoded[6..8].copy_from_slice(&sequence.to_be_bytes());
                encoded[8..].copy_from_slice(payload);
            }
            Icmpv6Message::DestinationUnreachable { code, quote } => {
                encoded[0] = 1;
                encoded[1] = code;
                encoded[8..].copy_from_slice(quote);
            }
            Icmpv6Message::PacketTooBig { mtu, quote } => {
                encoded[0] = 2;
                encoded[4..8].copy_from_slice(&mtu.to_be_bytes());
                encoded[8..].copy_from_slice(quote);
            }
            Icmpv6Message::TimeExceeded { code, quote } => {
                encoded[0] = 3;
                encoded[1] = code;
                encoded[8..].copy_from_slice(quote);
            }
            Icmpv6Message::ParameterProblem {
                code,
                pointer,
                quote,
            } => {
                encoded[0] = 4;
                encoded[1] = code;
                encoded[4..8].copy_from_slice(&pointer.to_be_bytes());
                encoded[8..].copy_from_slice(quote);
            }
        }
        let checksum = compute_transport_checksum(self.checksum_context, ICMPV6_PROTOCOL, encoded)
            .ok_or(BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            })?;
        encoded[2..4].copy_from_slice(&checksum.to_be_bytes());
        Ok(encoded)
    }

    /// Builds an exactly sized `ICMPv6` message.
    ///
    /// # Errors
    ///
    /// Returns semantic or length errors before exposing output.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0_u8; required];
        self.write_into(&mut output)?;
        Ok(output)
    }
}

/// Non-fatal `ICMPv6` compatibility observations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Icmpv6Conformance(u8);

impl Icmpv6Conformance {
    pub const RESERVED_FIELD_NONZERO: Self = Self(1 << 0);
    pub const UNKNOWN_CODE: Self = Self(1 << 1);

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

/// One parsed scanner-relevant, NDP, or safely unknown `ICMPv6` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedIcmpv6Message<'a> {
    EchoRequest {
        identifier: u16,
        sequence: u16,
        payload: &'a [u8],
    },
    EchoReply {
        identifier: u16,
        sequence: u16,
        payload: &'a [u8],
    },
    DestinationUnreachable {
        code: u8,
        quote: &'a [u8],
        quoted_packet: Result<QuotedIpPacket<'a>, ParseError>,
    },
    PacketTooBig {
        mtu: u32,
        quote: &'a [u8],
        quoted_packet: Result<QuotedIpPacket<'a>, ParseError>,
    },
    TimeExceeded {
        code: u8,
        quote: &'a [u8],
        quoted_packet: Result<QuotedIpPacket<'a>, ParseError>,
    },
    ParameterProblem {
        code: u8,
        pointer: u32,
        quote: &'a [u8],
        quoted_packet: Result<QuotedIpPacket<'a>, ParseError>,
    },
    NeighborDiscovery {
        message_type: u8,
        body: &'a [u8],
    },
    Unknown {
        message_type: u8,
        code: u8,
        body: &'a [u8],
    },
}

/// A pseudo-header-checksum-validated `ICMPv6` packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIcmpv6Packet<'a> {
    pub checksum: u16,
    pub message: ParsedIcmpv6Message<'a>,
    pub conformance: Icmpv6Conformance,
}

/// Parses and pseudo-header-checksum-validates one complete `ICMPv6` message.
///
/// # Errors
///
/// Returns non-IPv6 context, outer length, or checksum errors.
#[allow(
    clippy::too_many_lines,
    reason = "the length-first ICMPv6 type dispatch remains in wire order for auditability"
)]
pub fn parse_icmpv6_message(
    input: &[u8],
    checksum_context: TransportChecksumContext,
) -> Result<ParsedIcmpv6Packet<'_>, ParseError> {
    if !matches!(checksum_context, TransportChecksumContext::Ipv6 { .. }) {
        return Err(ParseError::Malformed {
            layer: Layer::Icmpv6,
            field: Field::Address,
        });
    }
    if input.len() > MAX_ICMPV6_MESSAGE_BYTES {
        return Err(ParseError::LimitExceeded {
            resource: Resource::TransportBytes,
            actual: input.len(),
            maximum: MAX_ICMPV6_MESSAGE_BYTES,
        });
    }
    if input.len() < ICMPV6_HEADER_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Icmpv6,
            required: ICMPV6_HEADER_LENGTH,
            actual: input.len(),
        });
    }
    if !validate_transport_checksum(checksum_context, ICMPV6_PROTOCOL, input) {
        return Err(ParseError::Malformed {
            layer: Layer::Icmpv6,
            field: Field::Checksum,
        });
    }
    let message_type = input[0];
    let code = input[1];
    let mut conformance = Icmpv6Conformance::default();
    let message = match message_type {
        128 | 129 if code == 0 => {
            let identifier = u16::from_be_bytes([input[4], input[5]]);
            let sequence = u16::from_be_bytes([input[6], input[7]]);
            if message_type == 128 {
                ParsedIcmpv6Message::EchoRequest {
                    identifier,
                    sequence,
                    payload: &input[8..],
                }
            } else {
                ParsedIcmpv6Message::EchoReply {
                    identifier,
                    sequence,
                    payload: &input[8..],
                }
            }
        }
        1 => {
            if code > 7 {
                conformance.insert(Icmpv6Conformance::UNKNOWN_CODE);
            }
            if input[4..8].iter().any(|byte| *byte != 0) {
                conformance.insert(Icmpv6Conformance::RESERVED_FIELD_NONZERO);
            }
            let quote = &input[8..];
            ParsedIcmpv6Message::DestinationUnreachable {
                code,
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        2 => {
            if code != 0 {
                conformance.insert(Icmpv6Conformance::UNKNOWN_CODE);
            }
            let quote = &input[8..];
            ParsedIcmpv6Message::PacketTooBig {
                mtu: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        3 => {
            if code > 1 {
                conformance.insert(Icmpv6Conformance::UNKNOWN_CODE);
            }
            if input[4..8].iter().any(|byte| *byte != 0) {
                conformance.insert(Icmpv6Conformance::RESERVED_FIELD_NONZERO);
            }
            let quote = &input[8..];
            ParsedIcmpv6Message::TimeExceeded {
                code,
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        4 => {
            if code > 2 {
                conformance.insert(Icmpv6Conformance::UNKNOWN_CODE);
            }
            let quote = &input[8..];
            ParsedIcmpv6Message::ParameterProblem {
                code,
                pointer: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        133..=137 if code == 0 => ParsedIcmpv6Message::NeighborDiscovery {
            message_type,
            body: &input[4..],
        },
        _ => {
            if matches!(message_type, 128 | 129 | 133..=137) {
                conformance.insert(Icmpv6Conformance::UNKNOWN_CODE);
            }
            ParsedIcmpv6Message::Unknown {
                message_type,
                code,
                body: &input[4..],
            }
        }
    };
    Ok(ParsedIcmpv6Packet {
        checksum: u16::from_be_bytes([input[2], input[3]]),
        message,
        conformance,
    })
}

fn validate_error_quote_v6(quote: &[u8]) -> Result<(), BuildError> {
    let parsed = parse_quoted_ip_packet(quote).map_err(|_| BuildError::InvalidValue {
        field: Field::PayloadLength,
    })?;
    if !matches!(parsed.source, IpAddress::V6(_)) {
        return Err(BuildError::InvalidValue {
            field: Field::PayloadLength,
        });
    }
    Ok(())
}
