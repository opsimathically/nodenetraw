use core::fmt;
use std::io;

/// Bounded resources named in stable snapshot failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SnapshotResource {
    DatagramBytes,
    DumpBytes,
    DumpMessages,
    MessageAttributes,
    AttributeDepth,
    StringBytes,
    Interfaces,
    Addresses,
    Routes,
    Rules,
    Neighbors,
    MultipathNextHops,
    LinkLayerAddressBytes,
    BufferedNotifications,
    BufferedNotificationBytes,
    PendingRouteQueries,
    UnknownAttributeBytes,
    SnapshotUnknownBytes,
}

/// Reasons a dump cannot be published as authoritative.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IncompleteReason {
    DumpInterrupted,
    Overrun,
    ReceiveBufferOverflow,
    SequenceMismatch,
    SenderNotKernel,
    HeaderPortMismatch,
    DatagramTruncated,
    MissingTerminator,
    GenerationChanged,
    KernelError(i32),
    UnexpectedMessage,
    DisappearingInterface(u32),
}

/// Read-only context creation and snapshot failures.
#[derive(Debug)]
pub enum SnapshotError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Decode {
        context: &'static str,
        detail: String,
    },
    LimitExceeded {
        resource: SnapshotResource,
        actual: usize,
        maximum: usize,
    },
    Incomplete {
        reason: IncompleteReason,
        attempts: usize,
    },
    UnsupportedAddressFamily(u8),
    InvalidQuery(String),
    Cancelled,
    DeadlineExceeded,
    ContextUnavailable,
}

impl SnapshotError {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    pub(crate) fn decode(context: &'static str, detail: impl fmt::Display) -> Self {
        Self::Decode {
            context,
            detail: detail.to_string(),
        }
    }

    pub(crate) const fn incomplete(reason: IncompleteReason) -> Self {
        Self::Incomplete {
            reason,
            attempts: 1,
        }
    }

    pub(crate) fn with_attempts(self, attempts: usize) -> Self {
        match self {
            Self::Incomplete { reason, .. } => Self::Incomplete { reason, attempts },
            other => other,
        }
    }

    pub(crate) const fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Decode { context, detail } => write!(formatter, "{context}: {detail}"),
            Self::LimitExceeded {
                resource,
                actual,
                maximum,
            } => write!(
                formatter,
                "{resource:?} limit exceeded: {actual} is greater than {maximum}"
            ),
            Self::Incomplete { reason, attempts } => write!(
                formatter,
                "network snapshot incomplete after {attempts} attempt(s): {reason:?}"
            ),
            Self::UnsupportedAddressFamily(family) => {
                write!(formatter, "unsupported netlink address family {family}")
            }
            Self::InvalidQuery(detail) => write!(formatter, "invalid route query: {detail}"),
            Self::Cancelled => formatter.write_str("route query was cancelled"),
            Self::DeadlineExceeded => formatter.write_str("route query deadline exceeded"),
            Self::ContextUnavailable => {
                formatter.write_str("no complete context generation exists")
            }
        }
    }
}

impl std::error::Error for SnapshotError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
