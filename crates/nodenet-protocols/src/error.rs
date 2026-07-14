use core::fmt;

use crate::PacketKind;

/// Stable protocol layer identifiers used by parse failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Layer {
    Link,
    Vlan,
    Arp,
    Network,
    Ipv4,
    Ipv6,
    Ipv6Extension,
    Transport,
    Icmpv4,
    Icmpv6,
    Ndp,
    Udp,
    Tcp,
    Payload,
}

/// Stable field identifiers used by validation failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Field {
    Address,
    AddressLength,
    Acknowledgment,
    Checksum,
    Code,
    Dscp,
    Ecn,
    ExtensionLength,
    ExtensionOrder,
    Flags,
    FlowLabel,
    FragmentOffset,
    HardwareType,
    HeaderLength,
    Operation,
    OptionKind,
    OptionLength,
    PacketLength,
    PayloadLength,
    Port,
    Protocol,
    ProtocolType,
    Sequence,
    Span,
    TemplateDescriptor,
    TemplatePatch,
    TotalLength,
    TrafficClass,
    Type,
    UrgentPointer,
    Version,
    VlanCount,
    VlanIdentifier,
    VlanPriority,
    Window,
}

/// Bounded resources reported by parser limit failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Resource {
    FrameBytes,
    IpPacketBytes,
    Ipv6ExtensionBytes,
    Ipv6ExtensionHeaders,
    NdpOptionBytes,
    NdpOptions,
    OwnedOptions,
    OwnedPayload,
    TemplateDescriptors,
    TcpOptionBytes,
    TcpOptions,
    TransportBytes,
    VlanHeaders,
}

/// Structured, dependency-independent packet parsing failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParseError {
    Truncated {
        layer: Layer,
        required: usize,
        actual: usize,
    },
    Malformed {
        layer: Layer,
        field: Field,
    },
    Unsupported {
        layer: Layer,
        field: Field,
    },
    LimitExceeded {
        resource: Resource,
        actual: usize,
        maximum: usize,
    },
    ArithmeticOverflow {
        field: Field,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                layer,
                required,
                actual,
            } => write!(
                formatter,
                "truncated {layer:?}: requires {required} bytes, received {actual}"
            ),
            Self::Malformed { layer, field } => {
                write!(formatter, "malformed {field:?} in {layer:?}")
            }
            Self::Unsupported { layer, field } => {
                write!(formatter, "unsupported {field:?} in {layer:?}")
            }
            Self::LimitExceeded {
                resource,
                actual,
                maximum,
            } => write!(
                formatter,
                "{resource:?} limit exceeded: {actual} is greater than {maximum}"
            ),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "arithmetic overflow while validating {field:?}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Structured packet construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BuildError {
    BufferTooSmall {
        required: usize,
        actual: usize,
    },
    LengthExceedsLimit {
        actual: usize,
        maximum: usize,
        kind: PacketKind,
    },
    InvalidValue {
        field: Field,
    },
    ArithmeticOverflow {
        field: Field,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { required, actual } => write!(
                formatter,
                "output buffer requires {required} bytes, received {actual}"
            ),
            Self::LengthExceedsLimit {
                actual,
                maximum,
                kind,
            } => write!(
                formatter,
                "{kind:?} length {actual} exceeds the {maximum}-byte ceiling"
            ),
            Self::InvalidValue { field } => write!(formatter, "invalid {field:?}"),
            Self::ArithmeticOverflow { field } => {
                write!(formatter, "arithmetic overflow while building {field:?}")
            }
        }
    }
}

impl std::error::Error for BuildError {}
