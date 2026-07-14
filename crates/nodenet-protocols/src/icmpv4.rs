use crate::{
    BuildError, Field, IpAddress, Layer, MAX_ICMPV4_MESSAGE_BYTES, PacketKind, PacketLength,
    ParseError, QuotedIpPacket, QuotedTransport, Resource, compute_internet_checksum,
    parse_quoted_ip_packet, validate_internet_checksum,
};

const ICMP_HEADER_LENGTH: usize = 8;

/// A canonical scanner-relevant `ICMPv4` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Icmpv4Message<'a> {
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
        next_hop_mtu: u16,
        quote: &'a [u8],
    },
    TimeExceeded {
        code: u8,
        quote: &'a [u8],
    },
    ParameterProblem {
        code: u8,
        pointer: u8,
        quote: &'a [u8],
    },
}

impl Icmpv4Message<'_> {
    /// Returns the checked encoded length after semantic quote validation.
    ///
    /// # Errors
    ///
    /// Rejects unsupported codes, malformed/short quotes, and size overflow.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        let variable_length = match self {
            Self::EchoRequest { payload, .. } | Self::EchoReply { payload, .. } => payload.len(),
            Self::DestinationUnreachable { code, quote, .. } => {
                if *code > 15 {
                    return Err(BuildError::InvalidValue { field: Field::Code });
                }
                validate_error_quote_v4(quote)?;
                quote.len()
            }
            Self::TimeExceeded { code, quote } => {
                if *code > 1 {
                    return Err(BuildError::InvalidValue { field: Field::Code });
                }
                validate_error_quote_v4(quote)?;
                quote.len()
            }
            Self::ParameterProblem { code, quote, .. } => {
                if *code > 2 {
                    return Err(BuildError::InvalidValue { field: Field::Code });
                }
                validate_error_quote_v4(quote)?;
                quote.len()
            }
        };
        let total = ICMP_HEADER_LENGTH.checked_add(variable_length).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            },
        )?;
        if total > MAX_ICMPV4_MESSAGE_BYTES {
            return Err(BuildError::LengthExceedsLimit {
                actual: total,
                maximum: MAX_ICMPV4_MESSAGE_BYTES,
                kind: PacketKind::Ip,
            });
        }
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Encodes a checksum-complete `ICMPv4` message transactionally.
    ///
    /// # Errors
    ///
    /// Returns before modifying `output` on semantic, length, or capacity error.
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
        match self {
            Self::EchoRequest {
                identifier,
                sequence,
                payload,
            }
            | Self::EchoReply {
                identifier,
                sequence,
                payload,
            } => {
                encoded[0] = if matches!(self, Self::EchoRequest { .. }) {
                    8
                } else {
                    0
                };
                encoded[4..6].copy_from_slice(&identifier.to_be_bytes());
                encoded[6..8].copy_from_slice(&sequence.to_be_bytes());
                encoded[8..].copy_from_slice(payload);
            }
            Self::DestinationUnreachable {
                code,
                next_hop_mtu,
                quote,
            } => {
                encoded[0] = 3;
                encoded[1] = code;
                if code == 4 {
                    encoded[6..8].copy_from_slice(&next_hop_mtu.to_be_bytes());
                }
                encoded[8..].copy_from_slice(quote);
            }
            Self::TimeExceeded { code, quote } => {
                encoded[0] = 11;
                encoded[1] = code;
                encoded[8..].copy_from_slice(quote);
            }
            Self::ParameterProblem {
                code,
                pointer,
                quote,
            } => {
                encoded[0] = 12;
                encoded[1] = code;
                encoded[4] = pointer;
                encoded[8..].copy_from_slice(quote);
            }
        }
        let checksum = compute_internet_checksum(encoded);
        encoded[2..4].copy_from_slice(&checksum.to_be_bytes());
        Ok(encoded)
    }

    /// Builds an exactly sized `ICMPv4` message.
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

/// Non-fatal `ICMPv4` compatibility observations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Icmpv4Conformance(u8);

impl Icmpv4Conformance {
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

/// One parsed scanner-relevant or safely unknown `ICMPv4` message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedIcmpv4Message<'a> {
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
        next_hop_mtu: Option<u16>,
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
        pointer: u8,
        quote: &'a [u8],
        quoted_packet: Result<QuotedIpPacket<'a>, ParseError>,
    },
    Unknown {
        message_type: u8,
        code: u8,
        body: &'a [u8],
    },
}

/// A checksum-validated `ICMPv4` message and conformance observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedIcmpv4Packet<'a> {
    pub checksum: u16,
    pub message: ParsedIcmpv4Message<'a>,
    pub conformance: Icmpv4Conformance,
}

/// Parses and checksum-validates one complete `ICMPv4` message.
///
/// Malformed quoted packets are retained as a nested `Err` and do not erase a
/// structurally valid outer ICMP error.
///
/// # Errors
///
/// Returns outer length or checksum errors.
#[allow(
    clippy::too_many_lines,
    reason = "the length-first ICMPv4 type dispatch remains in wire order for auditability"
)]
pub fn parse_icmpv4_message(input: &[u8]) -> Result<ParsedIcmpv4Packet<'_>, ParseError> {
    if input.len() > MAX_ICMPV4_MESSAGE_BYTES {
        return Err(ParseError::LimitExceeded {
            resource: Resource::TransportBytes,
            actual: input.len(),
            maximum: MAX_ICMPV4_MESSAGE_BYTES,
        });
    }
    if input.len() < ICMP_HEADER_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Icmpv4,
            required: ICMP_HEADER_LENGTH,
            actual: input.len(),
        });
    }
    if !validate_internet_checksum(input) {
        return Err(ParseError::Malformed {
            layer: Layer::Icmpv4,
            field: Field::Checksum,
        });
    }
    let message_type = input[0];
    let code = input[1];
    let mut conformance = Icmpv4Conformance::default();
    let message = match message_type {
        0 | 8 if code == 0 => {
            let identifier = u16::from_be_bytes([input[4], input[5]]);
            let sequence = u16::from_be_bytes([input[6], input[7]]);
            if message_type == 8 {
                ParsedIcmpv4Message::EchoRequest {
                    identifier,
                    sequence,
                    payload: &input[8..],
                }
            } else {
                ParsedIcmpv4Message::EchoReply {
                    identifier,
                    sequence,
                    payload: &input[8..],
                }
            }
        }
        3 => {
            if code > 15 {
                conformance.insert(Icmpv4Conformance::UNKNOWN_CODE);
            }
            if input[4] != 0 || input[5] != 0 || (code != 4 && (input[6] != 0 || input[7] != 0)) {
                conformance.insert(Icmpv4Conformance::RESERVED_FIELD_NONZERO);
            }
            let quote = &input[8..];
            ParsedIcmpv4Message::DestinationUnreachable {
                code,
                next_hop_mtu: (code == 4).then(|| u16::from_be_bytes([input[6], input[7]])),
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        11 => {
            if code > 1 {
                conformance.insert(Icmpv4Conformance::UNKNOWN_CODE);
            }
            if input[4..8].iter().any(|byte| *byte != 0) {
                conformance.insert(Icmpv4Conformance::RESERVED_FIELD_NONZERO);
            }
            let quote = &input[8..];
            ParsedIcmpv4Message::TimeExceeded {
                code,
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        12 => {
            if code > 2 {
                conformance.insert(Icmpv4Conformance::UNKNOWN_CODE);
            }
            if input[5..8].iter().any(|byte| *byte != 0) {
                conformance.insert(Icmpv4Conformance::RESERVED_FIELD_NONZERO);
            }
            let quote = &input[8..];
            ParsedIcmpv4Message::ParameterProblem {
                code,
                pointer: input[4],
                quote,
                quoted_packet: parse_quoted_ip_packet(quote),
            }
        }
        _ => {
            if matches!(message_type, 0 | 8) {
                conformance.insert(Icmpv4Conformance::UNKNOWN_CODE);
            }
            ParsedIcmpv4Message::Unknown {
                message_type,
                code,
                body: &input[4..],
            }
        }
    };
    Ok(ParsedIcmpv4Packet {
        checksum: u16::from_be_bytes([input[2], input[3]]),
        message,
        conformance,
    })
}

fn validate_error_quote_v4(quote: &[u8]) -> Result<(), BuildError> {
    let parsed = parse_quoted_ip_packet(quote).map_err(|_| BuildError::InvalidValue {
        field: Field::PayloadLength,
    })?;
    if !matches!(parsed.source, IpAddress::V4(_))
        || matches!(
            parsed.transport,
            QuotedTransport::Insufficient { .. }
                | QuotedTransport::NonFirstFragment { .. }
                | QuotedTransport::Opaque { .. }
        )
    {
        return Err(BuildError::InvalidValue {
            field: Field::PayloadLength,
        });
    }
    Ok(())
}
