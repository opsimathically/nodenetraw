use core::num::NonZeroU16;

use crate::{Field, MAX_OWNED_OPTION_BYTES, MAX_OWNED_PAYLOAD_BYTES, ParseError, Resource};

/// A six-octet IEEE MAC address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

/// An exact-width IPv4 address independent of platform socket types.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Address([u8; 4]);

impl Ipv4Address {
    #[must_use]
    pub const fn new(octets: [u8; 4]) -> Self {
        Self(octets)
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 4] {
        self.0
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Address {
    fn from(value: std::net::Ipv4Addr) -> Self {
        Self(value.octets())
    }
}

impl From<Ipv4Address> for std::net::Ipv4Addr {
    fn from(value: Ipv4Address) -> Self {
        Self::from(value.0)
    }
}

/// An exact-width IPv6 address independent of platform socket types.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv6Address([u8; 16]);

impl Ipv6Address {
    #[must_use]
    pub const fn new(octets: [u8; 16]) -> Self {
        Self(octets)
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 16] {
        self.0
    }
}

impl From<std::net::Ipv6Addr> for Ipv6Address {
    fn from(value: std::net::Ipv6Addr) -> Self {
        Self(value.octets())
    }
}

impl From<Ipv6Address> for std::net::Ipv6Addr {
    fn from(value: Ipv6Address) -> Self {
        Self::from(value.0)
    }
}

/// An exact-width IP address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpAddress {
    V4(Ipv4Address),
    V6(Ipv6Address),
}

/// A raw `EtherType` value; unknown registry values remain representable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EtherType(u16);

impl EtherType {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// An IPv4 protocol or IPv6 next-header number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IpProtocol(u8);

impl IpProtocol {
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A wire-format TCP or UDP port, including the reserved zero value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Port(u16);

impl Port {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A checked non-zero destination port suitable for an active probe.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProbePort(NonZeroU16);

impl ProbePort {
    /// Creates a destination port for an active probe.
    ///
    /// # Errors
    ///
    /// Returns [`crate::BuildError::InvalidValue`] for the reserved zero port.
    pub const fn new(value: u16) -> Result<Self, crate::BuildError> {
        match NonZeroU16::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(crate::BuildError::InvalidValue { field: Field::Port }),
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// A 16-bit Internet checksum in host integer form.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InternetChecksum(u16);

impl InternetChecksum {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

/// A range proven to lie wholly inside a packet slice.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketSpan {
    offset: usize,
    length: usize,
}

impl PacketSpan {
    /// Validates a range against the complete input length.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::ArithmeticOverflow`] if the end cannot be
    /// represented or [`ParseError::Truncated`] if it exceeds `input_length`.
    pub const fn new(
        offset: usize,
        length: usize,
        input_length: usize,
    ) -> Result<Self, ParseError> {
        let Some(end) = offset.checked_add(length) else {
            return Err(ParseError::ArithmeticOverflow { field: Field::Span });
        };
        if end > input_length {
            return Err(ParseError::Truncated {
                layer: crate::Layer::Payload,
                required: end,
                actual: input_length,
            });
        }
        Ok(Self { offset, length })
    }

    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    #[must_use]
    pub const fn length(self) -> usize {
        self.length
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.offset + self.length
    }

    #[must_use]
    pub fn get(self, input: &[u8]) -> Option<&[u8]> {
        input.get(self.offset..self.end())
    }
}

/// Controls whether declared wire lengths must be complete.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum ParseMode {
    /// Require all declared packet bytes to be present and structurally valid.
    #[default]
    Strict,
    /// Permit only the truncation expected inside a received ICMP error quote.
    CompatibleIcmpQuote,
}

/// A separately bounded owned payload copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPayload(Vec<u8>);

impl OwnedPayload {
    /// Copies a payload only after enforcing the owned-payload ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::LimitExceeded`] before allocation when the input
    /// is larger than [`MAX_OWNED_PAYLOAD_BYTES`].
    pub fn copy_from(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() > MAX_OWNED_PAYLOAD_BYTES {
            return Err(ParseError::LimitExceeded {
                resource: Resource::OwnedPayload,
                actual: input.len(),
                maximum: MAX_OWNED_PAYLOAD_BYTES,
            });
        }
        Ok(Self(input.to_vec()))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

/// A separately bounded owned protocol-option copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedOptions(Vec<u8>);

impl OwnedOptions {
    /// Copies option bytes only after enforcing the owned-options ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::LimitExceeded`] before allocation when the input
    /// is larger than [`MAX_OWNED_OPTION_BYTES`].
    pub fn copy_from(input: &[u8]) -> Result<Self, ParseError> {
        if input.len() > MAX_OWNED_OPTION_BYTES {
            return Err(ParseError::LimitExceeded {
                resource: Resource::OwnedOptions,
                actual: input.len(),
                maximum: MAX_OWNED_OPTION_BYTES,
            });
        }
        Ok(Self(input.to_vec()))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}
