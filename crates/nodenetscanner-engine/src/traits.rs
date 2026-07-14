use crate::{
    ContextFailure, ContextResolution, EngineError, LogicalProbe, MonotonicTime, ProbeEmission,
    ScanResult, SinkFailure, SinkReservation, TransportFailure,
};

/// Injected monotonic time source; implementations must never move backwards.
pub trait Clock {
    fn now(&self) -> MonotonicTime;
}

/// Injected public scheduling entropy, independent from correlation secrets.
pub trait EntropySource {
    /// # Errors
    ///
    /// Reports caller-specific entropy acquisition failure.
    fn scheduling_seed(&mut self) -> Result<u64, EngineError>;
}

/// Generic frame-emission boundary implemented by the Phase 22 data plane.
pub trait ProbeTransport {
    /// # Errors
    ///
    /// Returns a compact fatal transport error; the scheduler never retries an
    /// unknown partial send.
    fn emit(&mut self, emission: ProbeEmission) -> Result<(), TransportFailure>;
}

/// Policy-aware route context boundary implemented by Phase 20 integration.
pub trait ContextResolver {
    /// # Errors
    ///
    /// Returns a compact context-driver failure.
    fn resolve(&mut self, probe: LogicalProbe) -> Result<ContextResolution, ContextFailure>;
}

/// Lossless result capacity boundary. Reservations precede every first emission.
pub trait ResultSink {
    /// Reserves one terminal result slot without blocking the scheduler.
    ///
    /// # Errors
    ///
    /// Reports sink failure independently from ordinary saturation.
    fn try_reserve(&mut self) -> Result<SinkReservation, SinkFailure>;

    /// Consumes exactly one prior reservation.
    ///
    /// # Errors
    ///
    /// Reports a violated or failed sink contract.
    fn commit_reserved(&mut self, result: ScanResult) -> Result<(), SinkFailure>;

    /// Releases reservations when explicit close requests result disposal.
    ///
    /// # Errors
    ///
    /// Reports a violated or failed sink contract.
    fn release_reserved(&mut self, count: usize) -> Result<(), SinkFailure>;
}
