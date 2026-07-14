use crate::{
    BuildError, Field, IpProtocol, Layer, OwnedPayload, PacketKind, PacketLength, ParseError,
    Resource, TransportChecksumContext, compute_transport_checksum, validate_transport_checksum,
};

const UDP_HEADER_LENGTH: usize = 8;
const UDP_MAX_DATAGRAM_LENGTH: usize = 65_535;
const UDP_PROTOCOL: IpProtocol = IpProtocol::new(17);

/// Controls the IPv4-only UDP zero-checksum representation.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum UdpChecksumMode {
    #[default]
    Compute,
    OmitIpv4,
}

/// A borrowed UDP datagram builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    pub checksum_context: TransportChecksumContext,
    pub checksum_mode: UdpChecksumMode,
    pub source_port: crate::Port,
    pub destination_port: crate::Port,
    pub payload: &'a [u8],
}

impl UdpDatagram<'_> {
    /// Returns the checked complete UDP length.
    ///
    /// # Errors
    ///
    /// Rejects IPv6 checksum omission, overflow, or a length above 65,535.
    pub fn required_length(&self) -> Result<PacketLength, BuildError> {
        if self.checksum_mode == UdpChecksumMode::OmitIpv4
            && matches!(self.checksum_context, TransportChecksumContext::Ipv6 { .. })
        {
            return Err(BuildError::InvalidValue {
                field: Field::Checksum,
            });
        }
        let total = UDP_HEADER_LENGTH.checked_add(self.payload.len()).ok_or(
            BuildError::ArithmeticOverflow {
                field: Field::PayloadLength,
            },
        )?;
        if total > UDP_MAX_DATAGRAM_LENGTH {
            return Err(BuildError::LengthExceedsLimit {
                actual: total,
                maximum: UDP_MAX_DATAGRAM_LENGTH,
                kind: PacketKind::Ip,
            });
        }
        PacketLength::new(total, PacketKind::Ip)
    }

    /// Writes one UDP datagram without partial output on failure.
    ///
    /// # Errors
    ///
    /// Returns validation or short-buffer errors before modifying `output`.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.required_length()?.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..required];
        encoded[0..2].copy_from_slice(&self.source_port.get().to_be_bytes());
        encoded[2..4].copy_from_slice(&self.destination_port.get().to_be_bytes());
        encoded[4..6].copy_from_slice(&u16::try_from(required).unwrap_or(u16::MAX).to_be_bytes());
        encoded[6..8].fill(0);
        encoded[8..].copy_from_slice(self.payload);
        if self.checksum_mode == UdpChecksumMode::Compute {
            let checksum = compute_transport_checksum(self.checksum_context, UDP_PROTOCOL, encoded)
                .ok_or(BuildError::ArithmeticOverflow {
                    field: Field::PacketLength,
                })?;
            let transmitted = if checksum == 0 { u16::MAX } else { checksum };
            encoded[6..8].copy_from_slice(&transmitted.to_be_bytes());
        }
        Ok(encoded)
    }

    /// Builds an exactly sized UDP datagram.
    ///
    /// # Errors
    ///
    /// Returns validation errors before exposing output.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let required = self.required_length()?.get();
        let mut output = vec![0_u8; required];
        self.write_into(&mut output)?;
        Ok(output)
    }
}

/// Checksum meaning after family-specific UDP validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UdpChecksumStatus {
    Valid,
    NotPresentIpv4,
}

/// A borrowed validated UDP datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedUdpDatagram<'a> {
    pub source_port: crate::Port,
    pub destination_port: crate::Port,
    pub checksum: u16,
    pub checksum_status: UdpChecksumStatus,
    pub payload: &'a [u8],
    pub trailing: &'a [u8],
}

impl ParsedUdpDatagram<'_> {
    /// Copies the payload into an independently bounded owned result.
    ///
    /// # Errors
    ///
    /// Returns the owned-payload ceiling error before allocation.
    pub fn to_owned(self) -> Result<OwnedUdpDatagram, ParseError> {
        Ok(OwnedUdpDatagram {
            source_port: self.source_port,
            destination_port: self.destination_port,
            checksum: self.checksum,
            checksum_status: self.checksum_status,
            payload: OwnedPayload::copy_from(self.payload)?,
        })
    }
}

/// A UDP result whose payload ownership is independent of receive storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedUdpDatagram {
    pub source_port: crate::Port,
    pub destination_port: crate::Port,
    pub checksum: u16,
    pub checksum_status: UdpChecksumStatus,
    pub payload: OwnedPayload,
}

/// Parses a complete UDP header and its declared datagram bytes.
///
/// IPv4 checksum zero is reported as absent. IPv6 checksum zero is malformed.
/// Nonzero checksums are always validated against the supplied pseudo-header.
///
/// # Errors
///
/// Returns bounded length or family-specific checksum errors.
pub fn parse_udp_datagram(
    input: &[u8],
    checksum_context: TransportChecksumContext,
) -> Result<ParsedUdpDatagram<'_>, ParseError> {
    if input.len() > UDP_MAX_DATAGRAM_LENGTH {
        return Err(ParseError::LimitExceeded {
            resource: Resource::TransportBytes,
            actual: input.len(),
            maximum: UDP_MAX_DATAGRAM_LENGTH,
        });
    }
    if input.len() < UDP_HEADER_LENGTH {
        return Err(ParseError::Truncated {
            layer: Layer::Udp,
            required: UDP_HEADER_LENGTH,
            actual: input.len(),
        });
    }
    let declared_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
    if declared_length < UDP_HEADER_LENGTH {
        return Err(ParseError::Malformed {
            layer: Layer::Udp,
            field: Field::TotalLength,
        });
    }
    if input.len() < declared_length {
        return Err(ParseError::Truncated {
            layer: Layer::Udp,
            required: declared_length,
            actual: input.len(),
        });
    }
    let datagram = &input[..declared_length];
    let checksum = u16::from_be_bytes([input[6], input[7]]);
    let checksum_status = if checksum == 0 {
        if matches!(checksum_context, TransportChecksumContext::Ipv6 { .. }) {
            return Err(ParseError::Malformed {
                layer: Layer::Udp,
                field: Field::Checksum,
            });
        }
        UdpChecksumStatus::NotPresentIpv4
    } else {
        if !validate_transport_checksum(checksum_context, UDP_PROTOCOL, datagram) {
            return Err(ParseError::Malformed {
                layer: Layer::Udp,
                field: Field::Checksum,
            });
        }
        UdpChecksumStatus::Valid
    };
    Ok(ParsedUdpDatagram {
        source_port: crate::Port::new(u16::from_be_bytes([input[0], input[1]])),
        destination_port: crate::Port::new(u16::from_be_bytes([input[2], input[3]])),
        checksum,
        checksum_status,
        payload: &input[UDP_HEADER_LENGTH..declared_length],
        trailing: &input[declared_length..],
    })
}
