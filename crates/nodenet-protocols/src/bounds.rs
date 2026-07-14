use crate::BuildError;

/// Maximum IPv4 or non-jumbogram IPv6 packet length accepted by the toolkit.
pub const MAX_IP_PACKET_LENGTH: usize = 65_575;

/// Maximum Ethernet frame length with two VLAN tags and no captured FCS.
pub const MAX_ETHERNET_FRAME_LENGTH: usize = 65_597;

/// Maximum number of stacked 802.1Q/802.1ad VLAN headers.
pub const MAX_VLAN_HEADER_COUNT: usize = 2;

/// Maximum number of IPv6 extension headers traversed by a parser.
pub const MAX_IPV6_EXTENSION_HEADER_COUNT: usize = 8;

/// Maximum combined encoded length of IPv6 extension headers.
pub const MAX_IPV6_EXTENSION_BYTES: usize = 2_048;

/// Maximum TCP option length permitted by the TCP data-offset field.
pub const MAX_TCP_OPTION_BYTES: usize = 40;

/// Maximum number of decoded TCP options, including one-byte padding options.
pub const MAX_TCP_OPTION_COUNT: usize = MAX_TCP_OPTION_BYTES;

/// Maximum number of bounded IPv6 Neighbor Discovery options.
pub const MAX_NDP_OPTION_COUNT: usize = 64;

/// Maximum combined wire bytes retained while traversing NDP options.
pub const MAX_NDP_OPTION_BYTES: usize = 4_096;
/// Maximum simultaneously retained correlation source identifiers.
pub const MAX_CORRELATION_LEASES: usize = 262_144;

/// Maximum `ICMPv4` message inside a minimum-header IPv4 packet.
pub const MAX_ICMPV4_MESSAGE_BYTES: usize = 65_515;

/// Maximum `ICMPv6` message representable by the non-jumbogram payload field.
pub const MAX_ICMPV6_MESSAGE_BYTES: usize = 65_535;

/// Maximum payload copied into a returned owned value.
pub const MAX_OWNED_PAYLOAD_BYTES: usize = 65_535;

/// Maximum options copied into a returned owned value.
pub const MAX_OWNED_OPTION_BYTES: usize = MAX_IPV6_EXTENSION_BYTES;

/// Maximum checked mutable fields in one reusable frame template.
pub const MAX_TEMPLATE_PATCH_DESCRIPTORS: usize = 32;

/// Identifies the enclosing packet length ceiling.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PacketKind {
    /// An IPv4 or non-jumbogram IPv6 packet without a link header.
    Ip,
    /// An Ethernet frame with at most two VLAN headers and no captured FCS.
    Ethernet,
}

impl PacketKind {
    /// Returns the maximum encoded length for this packet kind.
    #[must_use]
    pub const fn maximum_length(self) -> usize {
        match self {
            Self::Ip => MAX_IP_PACKET_LENGTH,
            Self::Ethernet => MAX_ETHERNET_FRAME_LENGTH,
        }
    }
}

/// A packet length checked against its enclosing wire-format ceiling.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketLength {
    value: usize,
    kind: PacketKind,
}

impl PacketLength {
    /// Validates a packet length before allocation or output mutation.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::LengthExceedsLimit`] when `value` exceeds the
    /// ceiling for `kind`.
    pub const fn new(value: usize, kind: PacketKind) -> Result<Self, BuildError> {
        let maximum = kind.maximum_length();
        if value > maximum {
            return Err(BuildError::LengthExceedsLimit {
                actual: value,
                maximum,
                kind,
            });
        }
        Ok(Self { value, kind })
    }

    /// Returns the checked number of bytes.
    #[must_use]
    pub const fn get(self) -> usize {
        self.value
    }

    /// Returns the enclosing packet kind.
    #[must_use]
    pub const fn kind(self) -> PacketKind {
        self.kind
    }
}
