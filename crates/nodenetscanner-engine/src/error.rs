use core::fmt;

/// Stable target normalization failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetError {
    TooManyIncludes,
    TooManyExcludes,
    TooManyNormalizedIntervals,
    AddressFamilyMismatch,
    InvalidPrefixLength,
    ReversedRange,
    MissingIpv6Scope,
    UnexpectedScope,
    ZeroScope,
    ScopeMismatch,
    CidrCrossesScopeBoundary,
    TargetCountOverflow,
    Empty,
}

/// Stable scan-plan construction failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PlanError {
    NoProbes,
    TooManyProbeDefinitions,
    InvalidAttempts,
    DuplicateProbeFamily,
    PortsRequired,
    PortsNotAllowed,
    TooManyPorts,
    DuplicatePort,
    NoCompatibleTargets,
    LogicalProbeCountOverflow,
    LogicalProbeIndexOutOfRange,
}

/// Stable scheduler configuration failures.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConfigError {
    InvalidRate,
    InvalidBurst,
    InvalidOutstandingLimit,
    InvalidRetransmissions,
    InvalidTimeout,
    InvalidSessionDeadline,
    InvalidGraceCapacity,
    InvalidGraceDuration,
    InvalidTargetFairness,
    InvalidPrefixFairness,
}

/// Transport failures are compact and implementation-defined by numeric code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransportFailure {
    pub code: u32,
}

/// Context failures are compact and implementation-defined by numeric code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ContextFailure {
    pub code: u32,
}

/// Result-sink failures are compact and implementation-defined by numeric code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SinkFailure {
    pub code: u32,
}

/// Scheduler construction or state-machine failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EngineError {
    Target(TargetError),
    Plan(PlanError),
    Config(ConfigError),
    ClockRegressed,
    DeadlineOverflow,
    InvalidLifecycle,
    InvalidContext,
    InvalidEvidence,
    Transport(TransportFailure),
    Context(ContextFailure),
    Sink(SinkFailure),
    ReservationInvariant,
    StateCapacityExceeded,
}

impl From<TargetError> for EngineError {
    fn from(value: TargetError) -> Self {
        Self::Target(value)
    }
}

impl From<PlanError> for EngineError {
    fn from(value: PlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<ConfigError> for EngineError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "scanner engine: {self:?}")
    }
}

impl std::error::Error for EngineError {}
