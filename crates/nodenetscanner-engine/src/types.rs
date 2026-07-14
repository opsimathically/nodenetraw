use std::time::Duration;

use nodenet_protocols::{EvidenceStrength, IpAddress, ProbePort};

use crate::{ConfigError, EngineError};

/// Microsecond monotonic time used for deterministic arithmetic.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    pub(crate) const fn checked_add(self, duration: ScanDuration) -> Option<Self> {
        match self.0.checked_add(duration.0) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub(crate) const fn elapsed_since(self, earlier: Self) -> Option<ScanDuration> {
        match self.0.checked_sub(earlier.0) {
            Some(value) => Some(ScanDuration(value)),
            None => None,
        }
    }
}

/// Checked microsecond duration independent of wall-clock time.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScanDuration(u64);

impl ScanDuration {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }

    /// Converts a standard duration without truncating sub-microsecond values.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DeadlineOverflow`] if microseconds exceed `u64`.
    pub fn from_duration(value: Duration) -> Result<Self, EngineError> {
        let micros = value.as_micros();
        let rounded = if value.subsec_nanos().is_multiple_of(1_000) {
            micros
        } else {
            micros.checked_add(1).ok_or(EngineError::DeadlineOverflow)?
        };
        u64::try_from(rounded)
            .map(Self)
            .map_err(|_| EngineError::DeadlineOverflow)
    }

    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }

    pub(crate) fn saturating_mul(self, value: u32) -> Self {
        Self(self.0.saturating_mul(u64::from(value)))
    }
}

/// Optional IPv6 interface zone carried with one normalized target.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TargetScope(u32);

impl TargetScope {
    /// Creates a nonzero interface scope identifier.
    ///
    /// # Errors
    ///
    /// Rejects zero, which cannot identify an interface.
    pub const fn new(value: u32) -> Result<Self, crate::TargetError> {
        if value == 0 {
            Err(crate::TargetError::ZeroScope)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One exact normalized target address and optional IPv6 zone.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScanTarget {
    pub address: IpAddress,
    pub scope: Option<TargetScope>,
}

/// Probe families supported by the first portable scanner.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProbeFamily {
    Arp,
    Ndp,
    Icmpv4Echo,
    Icmpv6Echo,
    TcpSyn,
    Udp,
}

impl ProbeFamily {
    #[must_use]
    pub const fn uses_ports(self) -> bool {
        matches!(self, Self::TcpSyn | Self::Udp)
    }

    #[must_use]
    pub const fn supports_ipv4(self) -> bool {
        matches!(
            self,
            Self::Arp | Self::Icmpv4Echo | Self::TcpSyn | Self::Udp
        )
    }

    #[must_use]
    pub const fn supports_ipv6(self) -> bool {
        matches!(
            self,
            Self::Ndp | Self::Icmpv6Echo | Self::TcpSyn | Self::Udp
        )
    }
}

/// One lazily decoded logical probe tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LogicalProbe {
    pub logical_id: u64,
    pub attempt: u32,
    pub target: ScanTarget,
    pub family: ProbeFamily,
    pub port: Option<ProbePort>,
}

/// Scheduling seed origin and disclosure policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SchedulingSeed {
    Explicit(u64),
    Generated { value: u64, report: bool },
}

impl SchedulingSeed {
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Explicit(value) | Self::Generated { value, .. } => value,
        }
    }

    #[must_use]
    pub const fn reported(self) -> Option<u64> {
        match self {
            Self::Explicit(value)
            | Self::Generated {
                value,
                report: true,
            } => Some(value),
            Self::Generated { report: false, .. } => None,
        }
    }
}

/// Adaptive or explicitly fixed timeout behavior.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimingMode {
    Adaptive,
    FixedRate,
}

/// Silence policy for host-discovery probes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiscoverySilencePolicy {
    Unknown,
    DownByPolicy,
}

/// Fully checked state-machine configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    pub rate_per_second: u32,
    pub burst: u32,
    pub max_outstanding: usize,
    pub max_retransmissions: u8,
    pub initial_timeout: ScanDuration,
    pub minimum_timeout: ScanDuration,
    pub maximum_timeout: ScanDuration,
    pub session_deadline: ScanDuration,
    pub late_grace: ScanDuration,
    pub max_grace_entries: usize,
    pub max_per_target: usize,
    pub max_per_prefix: usize,
    pub timing_mode: TimingMode,
    pub discovery_silence: DiscoverySilencePolicy,
    pub tcp_reset_cleanup: bool,
}

impl SchedulerConfig {
    /// Validates every independent Phase 21 ceiling.
    ///
    /// # Errors
    ///
    /// Returns a specific [`ConfigError`] before scheduler state is allocated.
    pub fn validate(self) -> Result<Self, ConfigError> {
        use crate::{
            MAX_LATE_GRACE_ENTRIES, MAX_OUTSTANDING_PROBES, MAX_PROBE_TIMEOUT, MAX_RETRANSMISSIONS,
            MAX_SESSION_DURATION, MAX_TRANSMIT_RATE_PER_SECOND,
        };
        if self.rate_per_second == 0 || self.rate_per_second > MAX_TRANSMIT_RATE_PER_SECOND {
            return Err(ConfigError::InvalidRate);
        }
        if self.burst == 0
            || usize::try_from(self.burst).unwrap_or(usize::MAX) > self.max_outstanding
        {
            return Err(ConfigError::InvalidBurst);
        }
        if self.max_outstanding == 0 || self.max_outstanding > MAX_OUTSTANDING_PROBES {
            return Err(ConfigError::InvalidOutstandingLimit);
        }
        if self.max_retransmissions > MAX_RETRANSMISSIONS {
            return Err(ConfigError::InvalidRetransmissions);
        }
        let maximum_timeout = ScanDuration::from_micros(
            u64::try_from(MAX_PROBE_TIMEOUT.as_micros()).unwrap_or(u64::MAX),
        );
        if self.initial_timeout == ScanDuration::ZERO
            || self.minimum_timeout == ScanDuration::ZERO
            || self.minimum_timeout > self.initial_timeout
            || self.initial_timeout > self.maximum_timeout
            || self.maximum_timeout > maximum_timeout
        {
            return Err(ConfigError::InvalidTimeout);
        }
        let maximum_session = ScanDuration::from_micros(
            u64::try_from(MAX_SESSION_DURATION.as_micros()).unwrap_or(u64::MAX),
        );
        if self.session_deadline == ScanDuration::ZERO || self.session_deadline > maximum_session {
            return Err(ConfigError::InvalidSessionDeadline);
        }
        if self.max_grace_entries == 0 || self.max_grace_entries > MAX_LATE_GRACE_ENTRIES {
            return Err(ConfigError::InvalidGraceCapacity);
        }
        if self.late_grace == ScanDuration::ZERO || self.late_grace > maximum_session {
            return Err(ConfigError::InvalidGraceDuration);
        }
        if self.max_per_target == 0 || self.max_per_target > self.max_outstanding {
            return Err(ConfigError::InvalidTargetFairness);
        }
        if self.max_per_prefix == 0 || self.max_per_prefix > self.max_outstanding {
            return Err(ConfigError::InvalidPrefixFairness);
        }
        Ok(self)
    }

    #[must_use]
    pub const fn accuracy_tradeoff_reported(self) -> bool {
        matches!(self.timing_mode, TimingMode::FixedRate)
    }
}

/// Scanner session lifecycle independent of Node promises.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionLifecycle {
    Created,
    Running,
    Pausing,
    Paused,
    Cancelling,
    Completed,
    Failed,
    Closed,
}

/// On-wire purpose charged independently to rate budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EmissionPurpose {
    NeighborSetup(ProbeFamily),
    Probe,
    TcpResetCleanup,
}

/// Compact route context consumed by the syscall-free scheduler.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResolvedContext {
    pub generation: u64,
    pub prefix_key: PrefixKey,
    pub neighbor_setup: Option<ProbeFamily>,
}

/// Prefix fairness key supplied or confirmed by context policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrefixKey {
    pub family: u8,
    pub high: u64,
    pub low: u64,
    pub prefix_length: u8,
    pub scope: Option<TargetScope>,
}

impl PrefixKey {
    #[must_use]
    pub fn default_for(target: ScanTarget) -> Self {
        match target.address {
            IpAddress::V4(value) => Self {
                family: 4,
                high: 0,
                low: u64::from(u32::from_be_bytes(value.octets()) & 0xffff_ff00),
                prefix_length: 24,
                scope: target.scope,
            },
            IpAddress::V6(value) => {
                let octets = value.octets();
                Self {
                    family: 6,
                    high: u64::from_be_bytes([
                        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                        octets[6], octets[7],
                    ]),
                    low: 0,
                    prefix_length: 64,
                    scope: target.scope,
                }
            }
        }
    }
}

/// Route/context resolution state for one candidate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ContextResolution {
    Ready(ResolvedContext),
    Pending,
    Invalidated { previous_generation: Option<u64> },
}

/// One frame emission request; the transport constructs actual bytes in Phase 22.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProbeEmission {
    pub probe_id: u64,
    pub probe: LogicalProbe,
    pub route_generation: u64,
    pub purpose: EmissionPurpose,
    pub transmission: u8,
}

/// Protocol-normalized response meaning supplied by the future receive path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvidenceKind {
    TcpSynAcknowledgment,
    TcpReset,
    EchoReply,
    UdpReply,
    IcmpPortUnreachable,
    IcmpOtherError,
    ExplicitUnreachable,
    ArpReply,
    NeighborAdvertisement,
    NeighborResolved,
}

/// Correlated evidence addressed to an outstanding probe ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EvidenceEvent {
    pub probe_id: u64,
    pub kind: EvidenceKind,
    pub strength: EvidenceStrength,
}

/// Structurally valid input that cannot safely classify a probe.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiagnosticKind {
    ForgedOrUnrelated,
    NonFirstFragment,
    OpaqueProtocol,
    InsufficientQuote,
}

/// Evidence-based network result states.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkState {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Up,
    Unreachable,
    Unknown,
    DownByPolicy,
}

/// Probe outcome separates network evidence from lifecycle interruption.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProbeOutcome {
    Network(NetworkState),
    Cancelled,
    SessionDeadline,
    TransportFailed,
    ContextInvalidated,
}

/// Why a terminal record was produced.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TerminalReason {
    Evidence(EvidenceKind),
    Timeout,
    Cancelled,
    SessionDeadline,
    TransportFailure(u32),
    ContextInvalidated,
}

/// One lossless compact terminal transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanResult {
    pub probe: LogicalProbe,
    pub outcome: ProbeOutcome,
    pub evidence_strength: Option<EvidenceStrength>,
    pub attempt: u32,
    pub transmissions: u8,
    pub rtt: Option<ScanDuration>,
    /// Terminal timestamp in microseconds from the session's monotonic origin.
    ///
    /// The Node batch boundary widens this to nanoseconds without involving
    /// wall time or losing integer precision.
    pub terminal_at: MonotonicTime,
    pub route_generation: u64,
    pub terminal_reason: TerminalReason,
}

/// Bounded diagnostic counters; saturation is explicit and never wraps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticCounters {
    pub forged_or_unrelated: u64,
    pub non_first_fragment: u64,
    pub opaque_protocol: u64,
    pub insufficient_quote: u64,
    pub duplicates: u64,
    pub late_responses: u64,
    pub context_invalidations: u64,
}

/// Nonblocking sink reservation outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SinkReservation {
    Reserved,
    Saturated,
}

/// Work performed and next scheduling boundary after one bounded drive call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriveReport {
    pub lifecycle: SessionLifecycle,
    pub transitions: usize,
    pub emissions: usize,
    pub results: usize,
    pub outstanding: usize,
    pub deferred: usize,
    pub grace: usize,
    pub sink_backpressured: bool,
    pub context_waiting: bool,
    pub next_wakeup: Option<MonotonicTime>,
}
