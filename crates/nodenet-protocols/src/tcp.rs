use core::ops::{BitOr, BitOrAssign};

use crate::{
    BuildError, Field, IpProtocol, Layer, MAX_TCP_OPTION_BYTES, MAX_TCP_OPTION_COUNT, PacketKind,
    PacketLength, ParseError, Resource, TransportChecksumContext, compute_transport_checksum,
    validate_transport_checksum,
};

const TCP_MIN_HEADER_LENGTH: usize = 20;
const TCP_MAX_SEGMENT_LENGTH: usize = 65_535;
const TCP_PROTOCOL: IpProtocol = IpProtocol::new(6);

/// The nine standardized TCP control bits, including ECN nonce concealment.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct TcpFlags(u16);

impl TcpFlags {
    pub const FIN: Self = Self(1 << 0);
    pub const SYN: Self = Self(1 << 1);
    pub const RST: Self = Self(1 << 2);
    pub const PSH: Self = Self(1 << 3);
    pub const ACK: Self = Self(1 << 4);
    pub const URG: Self = Self(1 << 5);
    pub const ECE: Self = Self(1 << 6);
    pub const CWR: Self = Self(1 << 7);
    pub const NS: Self = Self(1 << 8);
    const ALL: u16 = 0x01ff;

    /// Creates a checked standardized flag set.
    ///
    /// # Errors
    ///
    /// Returns an invalid-flags error when reserved bits are supplied.
    pub const fn from_bits(bits: u16) -> Result<Self, BuildError> {
        if bits & !Self::ALL != 0 {
            return Err(BuildError::InvalidValue {
                field: Field::Flags,
            });
        }
        Ok(Self(bits))
    }

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

impl BitOr for TcpFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// One selective-acknowledgment sequence interval.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpSackBlock {
    pub left_edge: u32,
    pub right_edge: u32,
}

/// A canonical TCP option supplied to the builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpOption<'a> {
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(&'a [TcpSackBlock]),
    Timestamp { value: u32, echo_reply: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

impl TcpOption<'_> {
    fn encoded_length(self) -> Result<usize, BuildError> {
        match self {
            Self::NoOperation => Ok(1),
            Self::MaximumSegmentSize(_) => Ok(4),
            Self::WindowScale(value) => {
                if value > 14 {
                    Err(BuildError::InvalidValue {
                        field: Field::OptionLength,
                    })
                } else {
                    Ok(3)
                }
            }
            Self::SackPermitted => Ok(2),
            Self::Sack(blocks) => {
                if blocks.is_empty() || blocks.len() > 4 {
                    return Err(BuildError::InvalidValue {
                        field: Field::OptionLength,
                    });
                }
                Ok(2 + blocks.len() * 8)
            }
            Self::Timestamp { .. } => Ok(10),
            Self::Unknown { kind, data } => {
                if matches!(kind, 0 | 1 | 2 | 3 | 4 | 5 | 8) || data.len() > 253 {
                    return Err(BuildError::InvalidValue {
                        field: Field::OptionKind,
                    });
                }
                Ok(data.len() + 2)
            }
        }
    }
}

/// A borrowed canonical TCP segment builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    pub checksum_context: TransportChecksumContext,
    pub source_port: crate::Port,
    pub destination_port: crate::Port,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub urgent_pointer: u16,
    pub options: &'a [TcpOption<'a>],
    pub payload: &'a [u8],
}

impl TcpSegment<'_> {
    /// Returns the checked complete segment length.
    ///
    /// # Errors
    ///
    /// Returns invalid option/flag combinations or the transport size ceiling.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        let option_length = validate_options(self.options)?;
        if !self.flags.contains(TcpFlags::URG) && self.urgent_pointer != 0 {
            return Err(BuildError::InvalidValue {
                field: Field::UrgentPointer,
            });
        }
        let total = TCP_MIN_HEADER_LENGTH
            .checked_add(option_length)
            .and_then(|header| header.checked_add(self.payload.len()))
            .ok_or(BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            })?;
        if total > TCP_MAX_SEGMENT_LENGTH {
            return Err(BuildError::LengthExceedsLimit {
                actual: total,
                maximum: TCP_MAX_SEGMENT_LENGTH,
                kind: PacketKind::Ip,
            });
        }
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Writes a checksum-complete TCP segment transactionally.
    ///
    /// # Errors
    ///
    /// Returns before modifying `output` on validation or capacity failure.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.required_length()?.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..required];
        encode_tcp(self, encoded);
        let checksum = compute_transport_checksum(self.checksum_context, TCP_PROTOCOL, encoded)
            .ok_or(BuildError::ArithmeticOverflow {
                field: Field::PacketLength,
            })?;
        encoded[16..18].copy_from_slice(&checksum.to_be_bytes());
        Ok(encoded)
    }

    /// Builds an exactly sized checksum-complete TCP segment.
    ///
    /// # Errors
    ///
    /// Returns validation or length errors before exposing output.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0_u8; required];
        self.write_into(&mut output)?;
        Ok(output)
    }
}

/// Non-fatal TCP wire observations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct TcpConformance(u8);

impl TcpConformance {
    pub const RESERVED_BITS_SET: Self = Self(1 << 0);
    pub const NONZERO_OPTION_PADDING: Self = Self(1 << 1);
    pub const EXCESSIVE_WINDOW_SCALE: Self = Self(1 << 2);

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

/// Borrowed SACK blocks validated to a whole number of eight-byte intervals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedTcpSackBlocks<'a>(&'a [u8]);

impl ParsedTcpSackBlocks<'_> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len() / 8
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = TcpSackBlock> + '_ {
        self.0.chunks_exact(8).map(|bytes| TcpSackBlock {
            left_edge: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            right_edge: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// One safely decoded TCP option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedTcpOption<'a> {
    EndOfList,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(ParsedTcpSackBlocks<'a>),
    Timestamp { value: u32, echo_reply: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

/// Fixed-capacity decoded TCP option sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedTcpOptions<'a> {
    entries: [Option<ParsedTcpOption<'a>>; MAX_TCP_OPTION_COUNT],
    length: usize,
}

impl<'a> ParsedTcpOptions<'a> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[must_use]
    pub fn get(&self, index: usize) -> Option<ParsedTcpOption<'a>> {
        self.entries.get(index).copied().flatten()
    }

    pub fn iter(&self) -> impl Iterator<Item = ParsedTcpOption<'a>> + '_ {
        self.entries[..self.length].iter().copied().flatten()
    }

    fn push(&mut self, option: ParsedTcpOption<'a>) -> Result<(), ParseError> {
        if self.length == MAX_TCP_OPTION_COUNT {
            return Err(ParseError::LimitExceeded {
                resource: Resource::TcpOptions,
                actual: self.length + 1,
                maximum: MAX_TCP_OPTION_COUNT,
            });
        }
        self.entries[self.length] = Some(option);
        self.length += 1;
        Ok(())
    }
}

impl Default for ParsedTcpOptions<'_> {
    fn default() -> Self {
        Self {
            entries: [None; MAX_TCP_OPTION_COUNT],
            length: 0,
        }
    }
}

/// A checksum-validated borrowed TCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedTcpSegment<'a> {
    pub source_port: crate::Port,
    pub destination_port: crate::Port,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub flags: TcpFlags,
    pub reserved_bits: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: ParsedTcpOptions<'a>,
    pub payload: &'a [u8],
    pub conformance: TcpConformance,
}

/// Parses and pseudo-header-checksum-validates a complete TCP segment.
///
/// # Errors
///
/// Returns bounded length, data-offset, option, or checksum errors.
pub fn parse_tcp_segment(
    input: &[u8],
    checksum_context: TransportChecksumContext,
) -> Result<ParsedTcpSegment<'_>, ParseError> {
    if input.len() > TCP_MAX_SEGMENT_LENGTH {
        return Err(ParseError::LimitExceeded {
            resource: Resource::TransportBytes,
            actual: input.len(),
            maximum: TCP_MAX_SEGMENT_LENGTH,
        });
    }
    if input.len() < TCP_MIN_HEADER_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Tcp,
            required: TCP_MIN_HEADER_LENGTH,
            actual: input.len(),
        });
    }
    let data_offset = usize::from(input[12] >> 4);
    if data_offset < 5 {
        return Err(ParseError::Malformed {
            layer: Layer::Tcp,
            field: Field::HeaderLength,
        });
    }
    let header_length = data_offset * 4;
    if input.len() < header_length {
        return Err(ParseError::Truncated {
            layer: Layer::Tcp,
            required: header_length,
            actual: input.len(),
        });
    }
    if !validate_transport_checksum(checksum_context, TCP_PROTOCOL, input) {
        return Err(ParseError::Malformed {
            layer: Layer::Tcp,
            field: Field::Checksum,
        });
    }

    let reserved_bits = (input[12] >> 1) & 0x07;
    let mut conformance = TcpConformance::default();
    if reserved_bits != 0 {
        conformance.insert(TcpConformance::RESERVED_BITS_SET);
    }
    let flags = TcpFlags::from_bits((u16::from(input[12] & 1) << 8) | u16::from(input[13]))
        .map_err(|_| ParseError::Malformed {
            layer: Layer::Tcp,
            field: Field::Flags,
        })?;
    let (options, option_conformance) = parse_options(&input[20..header_length])?;
    conformance.0 |= option_conformance.0;
    Ok(ParsedTcpSegment {
        source_port: crate::Port::new(u16::from_be_bytes([input[0], input[1]])),
        destination_port: crate::Port::new(u16::from_be_bytes([input[2], input[3]])),
        sequence_number: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
        acknowledgment_number: u32::from_be_bytes([input[8], input[9], input[10], input[11]]),
        flags,
        reserved_bits,
        window_size: u16::from_be_bytes([input[14], input[15]]),
        checksum: u16::from_be_bytes([input[16], input[17]]),
        urgent_pointer: u16::from_be_bytes([input[18], input[19]]),
        options,
        payload: &input[header_length..],
        conformance,
    })
}

fn validate_options(options: &[TcpOption<'_>]) -> Result<usize, BuildError> {
    if options.len() > MAX_TCP_OPTION_COUNT {
        return Err(BuildError::InvalidValue {
            field: Field::OptionLength,
        });
    }
    let mut length = 0_usize;
    for option in options.iter().copied() {
        length =
            length
                .checked_add(option.encoded_length()?)
                .ok_or(BuildError::ArithmeticOverflow {
                    field: Field::OptionLength,
                })?;
    }
    let padded =
        length
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or(BuildError::ArithmeticOverflow {
                field: Field::OptionLength,
            })?;
    if padded > MAX_TCP_OPTION_BYTES {
        return Err(BuildError::InvalidValue {
            field: Field::OptionLength,
        });
    }
    Ok(padded)
}

fn encode_tcp(segment: TcpSegment<'_>, output: &mut [u8]) {
    let option_length = validate_options(segment.options).unwrap_or_default();
    let header_length = TCP_MIN_HEADER_LENGTH + option_length;
    output[..header_length].fill(0);
    output[0..2].copy_from_slice(&segment.source_port.get().to_be_bytes());
    output[2..4].copy_from_slice(&segment.destination_port.get().to_be_bytes());
    output[4..8].copy_from_slice(&segment.sequence_number.to_be_bytes());
    output[8..12].copy_from_slice(&segment.acknowledgment_number.to_be_bytes());
    output[12] = (u8::try_from(header_length / 4).unwrap_or(15) << 4)
        | u8::try_from((segment.flags.bits() >> 8) & 1).unwrap_or_default();
    output[13] = segment.flags.bits().to_be_bytes()[1];
    output[14..16].copy_from_slice(&segment.window_size.to_be_bytes());
    output[16..18].fill(0);
    output[18..20].copy_from_slice(&segment.urgent_pointer.to_be_bytes());
    let mut cursor = TCP_MIN_HEADER_LENGTH;
    for option in segment.options.iter().copied() {
        cursor += encode_option(option, &mut output[cursor..header_length]);
    }
    output[header_length..].copy_from_slice(segment.payload);
}

fn encode_option(option: TcpOption<'_>, output: &mut [u8]) -> usize {
    match option {
        TcpOption::NoOperation => {
            output[0] = 1;
            1
        }
        TcpOption::MaximumSegmentSize(value) => {
            output[0..2].copy_from_slice(&[2, 4]);
            output[2..4].copy_from_slice(&value.to_be_bytes());
            4
        }
        TcpOption::WindowScale(value) => {
            output[0..3].copy_from_slice(&[3, 3, value]);
            3
        }
        TcpOption::SackPermitted => {
            output[0..2].copy_from_slice(&[4, 2]);
            2
        }
        TcpOption::Sack(blocks) => {
            let length = 2 + blocks.len() * 8;
            output[0] = 5;
            output[1] = u8::try_from(length).unwrap_or_default();
            for (index, block) in blocks.iter().copied().enumerate() {
                let offset = 2 + index * 8;
                output[offset..offset + 4].copy_from_slice(&block.left_edge.to_be_bytes());
                output[offset + 4..offset + 8].copy_from_slice(&block.right_edge.to_be_bytes());
            }
            length
        }
        TcpOption::Timestamp { value, echo_reply } => {
            output[0..2].copy_from_slice(&[8, 10]);
            output[2..6].copy_from_slice(&value.to_be_bytes());
            output[6..10].copy_from_slice(&echo_reply.to_be_bytes());
            10
        }
        TcpOption::Unknown { kind, data } => {
            let length = data.len() + 2;
            output[0] = kind;
            output[1] = u8::try_from(length).unwrap_or_default();
            output[2..length].copy_from_slice(data);
            length
        }
    }
}

fn parse_options(input: &[u8]) -> Result<(ParsedTcpOptions<'_>, TcpConformance), ParseError> {
    let mut options = ParsedTcpOptions::default();
    let mut conformance = TcpConformance::default();
    let mut cursor = 0;
    while cursor < input.len() {
        let kind = input[cursor];
        if kind == 0 {
            options.push(ParsedTcpOption::EndOfList)?;
            if input[cursor + 1..].iter().any(|byte| *byte != 0) {
                conformance.insert(TcpConformance::NONZERO_OPTION_PADDING);
            }
            break;
        }
        if kind == 1 {
            options.push(ParsedTcpOption::NoOperation)?;
            cursor += 1;
            continue;
        }
        let Some(&length_byte) = input.get(cursor + 1) else {
            return Err(ParseError::Malformed {
                layer: Layer::Tcp,
                field: Field::OptionLength,
            });
        };
        let length = usize::from(length_byte);
        let Some(end) = cursor.checked_add(length) else {
            return Err(ParseError::ArithmeticOverflow {
                field: Field::OptionLength,
            });
        };
        if length < 2 || end > input.len() {
            return Err(ParseError::Malformed {
                layer: Layer::Tcp,
                field: Field::OptionLength,
            });
        }
        let data = &input[cursor + 2..end];
        let option = match (kind, length) {
            (2, 4) => ParsedTcpOption::MaximumSegmentSize(u16::from_be_bytes([data[0], data[1]])),
            (3, 3) => {
                if data[0] > 14 {
                    conformance.insert(TcpConformance::EXCESSIVE_WINDOW_SCALE);
                }
                ParsedTcpOption::WindowScale(data[0])
            }
            (4, 2) => ParsedTcpOption::SackPermitted,
            (5, value) if value >= 10 && (value - 2).is_multiple_of(8) => {
                ParsedTcpOption::Sack(ParsedTcpSackBlocks(data))
            }
            (8, 10) => ParsedTcpOption::Timestamp {
                value: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                echo_reply: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            },
            (2 | 3 | 4 | 5 | 8, _) => {
                return Err(ParseError::Malformed {
                    layer: Layer::Tcp,
                    field: Field::OptionLength,
                });
            }
            _ => ParsedTcpOption::Unknown { kind, data },
        };
        options.push(option)?;
        cursor = end;
    }
    Ok((options, conformance))
}
