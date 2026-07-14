use std::collections::{BTreeMap, VecDeque};

use nodenet_protocols::EvidenceStrength;

use crate::{
    Clock, ContextResolution, ContextResolver, DiagnosticCounters, DiagnosticKind,
    DiscoverySilencePolicy, DriveReport, EmissionPurpose, EngineError, EvidenceEvent, EvidenceKind,
    LogicalProbe, MAX_DEFERRED_CANDIDATES, MAX_TRANSITIONS_PER_DRIVE, MonotonicTime, NetworkState,
    PrefixKey, ProbeEmission, ProbeFamily, ProbeOutcome, ProbeTransport, ResolvedContext,
    ResultSink, RttEstimator, ScanDuration, ScanPlan, ScanResult, SchedulerConfig,
    SeededPermutation, SessionLifecycle, SinkReservation, TerminalReason, TokenBucket,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveStage {
    Pending(EmissionPurpose),
    Waiting {
        purpose: EmissionPurpose,
        deadline: MonotonicTime,
    },
    PendingCleanup(PendingTerminal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTerminal {
    outcome: ProbeOutcome,
    strength: Option<EvidenceStrength>,
    rtt: Option<ScanDuration>,
    reason: TerminalReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveProbe {
    probe: LogicalProbe,
    context: ResolvedContext,
    stage: ActiveStage,
    stage_transmissions: u8,
    total_transmissions: u8,
    last_probe_sent_at: Option<MonotonicTime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StopState {
    outcome: ProbeOutcome,
    reason: TerminalReason,
    final_lifecycle: SessionLifecycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationFilter {
    All,
    Exact(u64),
}

impl GenerationFilter {
    const fn matches(self, generation: u64) -> bool {
        match self {
            Self::All => true,
            Self::Exact(expected) => generation == expected,
        }
    }
}

/// Bounded deterministic scan state machine.
pub struct ScanScheduler {
    plan: ScanPlan,
    config: SchedulerConfig,
    permutation: SeededPermutation,
    lifecycle: SessionLifecycle,
    session_deadline: Option<MonotonicTime>,
    last_now: Option<MonotonicTime>,
    cursor: u64,
    active: BTreeMap<u64, ActiveProbe>,
    grace: BTreeMap<u64, MonotonicTime>,
    deferred: VecDeque<LogicalProbe>,
    per_target: BTreeMap<crate::ScanTarget, usize>,
    per_prefix: BTreeMap<PrefixKey, usize>,
    bucket: Option<TokenBucket>,
    rtt: RttEstimator,
    diagnostics: DiagnosticCounters,
    context_waiting: bool,
    sink_backpressured: bool,
    stop: Option<StopState>,
    invalidating_generation: Option<GenerationFilter>,
}

impl ScanScheduler {
    /// Creates an allocation-bounded session in `Created` state.
    ///
    /// # Errors
    ///
    /// Rejects invalid configuration or an empty permutation domain before
    /// active/result state is allocated.
    pub fn new(
        plan: ScanPlan,
        config: SchedulerConfig,
        permutation: SeededPermutation,
    ) -> Result<Self, EngineError> {
        let config = config.validate()?;
        if permutation.length() != plan.logical_probe_count() {
            return Err(EngineError::Plan(
                crate::PlanError::LogicalProbeIndexOutOfRange,
            ));
        }
        Ok(Self {
            plan,
            config,
            permutation,
            lifecycle: SessionLifecycle::Created,
            session_deadline: None,
            last_now: None,
            cursor: 0,
            active: BTreeMap::new(),
            grace: BTreeMap::new(),
            deferred: VecDeque::new(),
            per_target: BTreeMap::new(),
            per_prefix: BTreeMap::new(),
            bucket: None,
            rtt: RttEstimator::default(),
            diagnostics: DiagnosticCounters::default(),
            context_waiting: false,
            sink_backpressured: false,
            stop: None,
            invalidating_generation: None,
        })
    }

    /// Starts the session at one injected monotonic instant.
    ///
    /// # Errors
    ///
    /// Rejects repeated start and deadline overflow.
    pub fn start(&mut self, clock: &impl Clock) -> Result<(), EngineError> {
        if self.lifecycle != SessionLifecycle::Created {
            return Err(EngineError::InvalidLifecycle);
        }
        let now = self.observe_now(clock)?;
        let deadline = now
            .checked_add(self.config.session_deadline)
            .ok_or(EngineError::DeadlineOverflow)?;
        self.session_deadline = Some(deadline);
        self.bucket = Some(TokenBucket::new(
            self.config.rate_per_second,
            self.config.burst,
            now,
        )?);
        self.lifecycle = SessionLifecycle::Running;
        Ok(())
    }

    #[must_use]
    pub const fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn diagnostics(&self) -> DiagnosticCounters {
        self.diagnostics
    }

    #[must_use]
    pub const fn reported_seed(&self) -> Option<u64> {
        self.permutation.reported_seed()
    }

    #[must_use]
    pub const fn accuracy_tradeoff_reported(&self) -> bool {
        self.config.accuracy_tradeoff_reported()
    }

    /// Requests a deterministic no-new-transmission boundary.
    ///
    /// # Errors
    ///
    /// Only a running session can pause.
    pub fn request_pause(&mut self) -> Result<(), EngineError> {
        if self.lifecycle != SessionLifecycle::Running {
            return Err(EngineError::InvalidLifecycle);
        }
        self.lifecycle = SessionLifecycle::Pausing;
        Ok(())
    }

    /// Resumes admission and retransmission.
    ///
    /// # Errors
    ///
    /// Only a paused session can resume.
    pub fn resume(&mut self) -> Result<(), EngineError> {
        if self.lifecycle != SessionLifecycle::Paused {
            return Err(EngineError::InvalidLifecycle);
        }
        self.lifecycle = SessionLifecycle::Running;
        Ok(())
    }

    /// Clears a context-invalidated admission boundary.
    pub fn context_restored(&mut self) {
        if self.invalidating_generation.is_none() {
            self.context_waiting = false;
        }
    }

    /// Runs at most [`MAX_TRANSITIONS_PER_DRIVE`] state transitions.
    ///
    /// # Errors
    ///
    /// Propagates clock, context, or sink contract failures.
    pub fn drive<C, T, R, S>(
        &mut self,
        clock: &C,
        transport: &mut T,
        resolver: &mut R,
        sink: &mut S,
    ) -> Result<DriveReport, EngineError>
    where
        C: Clock,
        T: ProbeTransport,
        R: ContextResolver,
        S: ResultSink,
    {
        if self.lifecycle == SessionLifecycle::Created || self.lifecycle == SessionLifecycle::Closed
        {
            return Err(EngineError::InvalidLifecycle);
        }
        let now = self.observe_now(clock)?;
        self.prune_grace(now);
        let mut report = MutableReport::default();
        self.sink_backpressured = false;
        if self.lifecycle == SessionLifecycle::Pausing {
            self.lifecycle = SessionLifecycle::Paused;
            report.transitions += 1;
        }
        if self.deadline_reached(now) && !self.is_terminal() && self.stop.is_none() {
            self.initiate_stop(
                ProbeOutcome::SessionDeadline,
                TerminalReason::SessionDeadline,
                SessionLifecycle::Completed,
            );
        }
        if self.stop.is_some() {
            self.settle_stop(now, sink, &mut report)?;
        }
        if self.stop.is_none() && self.invalidating_generation.is_some() {
            self.settle_context_invalidation(now, sink, &mut report)?;
        }
        if !self.is_terminal() && self.stop.is_none() && self.invalidating_generation.is_none() {
            self.process_timeouts(now, sink, &mut report)?;
        }
        if self.lifecycle == SessionLifecycle::Running {
            self.emit_pending(now, transport, sink, &mut report)?;
            if !self.context_waiting {
                self.admit(now, resolver, sink, &mut report)?;
            }
            self.emit_pending(now, transport, sink, &mut report)?;
        }
        self.complete_if_finished();
        self.make_report(now, report)
    }

    /// Applies one correlated evidence event at its exact clock boundary.
    ///
    /// # Errors
    ///
    /// Propagates clock, transport, or sink failures.
    pub fn handle_evidence<C, T, S>(
        &mut self,
        clock: &C,
        event: EvidenceEvent,
        transport: &mut T,
        sink: &mut S,
    ) -> Result<(), EngineError>
    where
        C: Clock,
        T: ProbeTransport,
        S: ResultSink,
    {
        let now = self.observe_now(clock)?;
        self.prune_grace(now);
        if self.deadline_reached(now) && !self.is_terminal() && self.stop.is_none() {
            self.initiate_stop(
                ProbeOutcome::SessionDeadline,
                TerminalReason::SessionDeadline,
                SessionLifecycle::Completed,
            );
            let mut report = MutableReport::default();
            self.settle_stop(now, sink, &mut report)?;
        }
        if self.stop.is_some() {
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            return Ok(());
        }
        if self.invalidating_generation.is_some() {
            let event_is_invalidated = self.active.get(&event.probe_id).is_some_and(|active| {
                self.invalidating_generation
                    .is_some_and(|filter| filter.matches(active.context.generation))
            });
            let mut report = MutableReport::default();
            self.settle_context_invalidation(now, sink, &mut report)?;
            if event_is_invalidated && self.active.contains_key(&event.probe_id) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
                return Ok(());
            }
        }
        if self.grace.contains_key(&event.probe_id) {
            self.diagnostics.duplicates = self.diagnostics.duplicates.saturating_add(1);
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            return Ok(());
        }
        let Some(active) = self.active.get(&event.probe_id).copied() else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        let ActiveStage::Waiting { purpose, deadline } = active.stage else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        if now >= deadline {
            let mut report = MutableReport::default();
            self.timeout_one(event.probe_id, now, sink, &mut report)?;
            self.diagnostics.late_responses = self.diagnostics.late_responses.saturating_add(1);
            return Ok(());
        }
        if let EmissionPurpose::NeighborSetup(setup) = purpose {
            if !valid_neighbor_evidence(setup, event.kind) {
                self.diagnostics.forged_or_unrelated =
                    self.diagnostics.forged_or_unrelated.saturating_add(1);
                return Ok(());
            }
            let active = self
                .active
                .get_mut(&event.probe_id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage = ActiveStage::Pending(EmissionPurpose::Probe);
            active.stage_transmissions = 0;
            return Ok(());
        }

        let Ok(mut terminal) = classify_terminal(active.probe, event) else {
            self.diagnostics.forged_or_unrelated =
                self.diagnostics.forged_or_unrelated.saturating_add(1);
            return Ok(());
        };
        terminal.rtt = active
            .last_probe_sent_at
            .and_then(|sent| now.elapsed_since(sent));
        if active.stage_transmissions == 1
            && let Some(sample) = terminal.rtt
        {
            self.rtt.observe(sample);
        }
        if self.config.tcp_reset_cleanup
            && active.probe.family == ProbeFamily::TcpSyn
            && event.kind == EvidenceKind::TcpSynAcknowledgment
        {
            let active = self
                .active
                .get_mut(&event.probe_id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage = ActiveStage::PendingCleanup(terminal);
            active.stage_transmissions = 0;
            let mut report = MutableReport::default();
            self.emit_pending(now, transport, sink, &mut report)?;
        } else {
            self.terminalize(event.probe_id, now, terminal, sink, None)?;
        }
        self.complete_if_finished();
        Ok(())
    }

    /// Increments one bounded diagnostic without guessing a result.
    pub fn record_diagnostic(&mut self, kind: DiagnosticKind) {
        let counter = match kind {
            DiagnosticKind::ForgedOrUnrelated => &mut self.diagnostics.forged_or_unrelated,
            DiagnosticKind::NonFirstFragment => &mut self.diagnostics.non_first_fragment,
            DiagnosticKind::OpaqueProtocol => &mut self.diagnostics.opaque_protocol,
            DiagnosticKind::InsufficientQuote => &mut self.diagnostics.insufficient_quote,
        };
        *counter = counter.saturating_add(1);
    }

    /// Invalidates active results joined to one route generation.
    ///
    /// # Errors
    ///
    /// Propagates sink failures while settling already-reserved records.
    pub fn invalidate_context(
        &mut self,
        clock: &impl Clock,
        generation: Option<u64>,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        let now = self.observe_now(clock)?;
        self.context_waiting = true;
        self.diagnostics.context_invalidations =
            self.diagnostics.context_invalidations.saturating_add(1);
        let filter = generation.map_or(GenerationFilter::All, GenerationFilter::Exact);
        if self
            .invalidating_generation
            .is_some_and(|active| active != filter)
        {
            return Err(EngineError::InvalidContext);
        }
        self.invalidating_generation = Some(filter);
        let mut report = MutableReport::default();
        self.settle_context_invalidation(now, sink, &mut report)
    }

    fn settle_context_invalidation<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let filter = self
            .invalidating_generation
            .ok_or(EngineError::ReservationInvariant)?;
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, active)| filter.matches(active.context.generation).then_some(*id))
            .take(remaining)
            .collect();
        for id in ids {
            self.terminalize(
                id,
                now,
                PendingTerminal {
                    outcome: ProbeOutcome::ContextInvalidated,
                    strength: None,
                    rtt: None,
                    reason: TerminalReason::ContextInvalidated,
                },
                sink,
                Some(report),
            )?;
        }
        if !self
            .active
            .values()
            .any(|active| filter.matches(active.context.generation))
        {
            self.invalidating_generation = None;
        }
        Ok(())
    }

    /// Cancels admitted work losslessly and stops future admission.
    ///
    /// # Errors
    ///
    /// Propagates clock or sink failures.
    pub fn cancel(
        &mut self,
        clock: &impl Clock,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        if !matches!(
            self.lifecycle,
            SessionLifecycle::Running | SessionLifecycle::Pausing | SessionLifecycle::Paused
        ) {
            return Err(EngineError::InvalidLifecycle);
        }
        let now = self.observe_now(clock)?;
        self.initiate_stop(
            ProbeOutcome::Cancelled,
            TerminalReason::Cancelled,
            SessionLifecycle::Completed,
        );
        let mut report = MutableReport::default();
        self.settle_stop(now, sink, &mut report)?;
        Ok(())
    }

    /// Fails every admitted probe after an unrecoverable transport boundary.
    ///
    /// # Errors
    ///
    /// Propagates clock or sink failures while draining reserved results.
    pub fn transport_failed(
        &mut self,
        clock: &impl Clock,
        code: u32,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        if self.is_terminal() || self.stop.is_some() {
            return Ok(());
        }
        let now = self.observe_now(clock)?;
        let mut report = MutableReport::default();
        self.fail_transport(now, code, sink, &mut report)
    }

    /// Fails every admitted probe after an unrecoverable context boundary.
    ///
    /// # Errors
    ///
    /// Propagates clock or sink failures while draining reserved results.
    pub fn context_failed(
        &mut self,
        clock: &impl Clock,
        sink: &mut impl ResultSink,
    ) -> Result<(), EngineError> {
        if self.is_terminal() || self.stop.is_some() {
            return Ok(());
        }
        let now = self.observe_now(clock)?;
        self.initiate_stop(
            ProbeOutcome::ContextInvalidated,
            TerminalReason::ContextInvalidated,
            SessionLifecycle::Failed,
        );
        let mut report = MutableReport::default();
        self.settle_stop(now, sink, &mut report)
    }

    /// Explicitly disposes admitted results and all correlation state.
    ///
    /// # Errors
    ///
    /// Propagates sink reservation-release failure.
    pub fn close(&mut self, sink: &mut impl ResultSink) -> Result<(), EngineError> {
        if self.lifecycle == SessionLifecycle::Closed {
            return Ok(());
        }
        sink.release_reserved(self.active.len())
            .map_err(EngineError::Sink)?;
        self.active.clear();
        self.grace.clear();
        self.deferred.clear();
        self.per_target.clear();
        self.per_prefix.clear();
        self.stop = None;
        self.invalidating_generation = None;
        self.lifecycle = SessionLifecycle::Closed;
        Ok(())
    }

    fn admit<R: ContextResolver, S: ResultSink>(
        &mut self,
        _now: MonotonicTime,
        resolver: &mut R,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let mut examined = 0_usize;
        let mut deferred_remaining = self.deferred.len();
        while self.active.len() < self.config.max_outstanding
            && report.transitions < MAX_TRANSITIONS_PER_DRIVE
            && self.grace.len() + self.active.len() < self.config.max_grace_entries
            && examined < MAX_TRANSITIONS_PER_DRIVE
        {
            let Some(probe) = self.next_candidate(&mut deferred_remaining)? else {
                break;
            };
            examined += 1;
            if self.per_target.get(&probe.target).copied().unwrap_or(0)
                >= self.config.max_per_target
            {
                self.defer(probe)?;
                report.transitions += 1;
                continue;
            }
            let resolution = match resolver.resolve(probe) {
                Ok(value) => value,
                Err(error) => {
                    self.requeue_front(probe)?;
                    return Err(EngineError::Context(error));
                }
            };
            let context = match resolution {
                ContextResolution::Ready(value) => value,
                ContextResolution::Pending => {
                    self.deferred.push_front(probe);
                    self.context_waiting = true;
                    report.transitions += 1;
                    break;
                }
                ContextResolution::Invalidated { .. } => {
                    self.deferred.push_front(probe);
                    self.context_waiting = true;
                    self.diagnostics.context_invalidations =
                        self.diagnostics.context_invalidations.saturating_add(1);
                    report.transitions += 1;
                    break;
                }
            };
            if !valid_neighbor_setup(probe, context.neighbor_setup) {
                self.requeue_front(probe)?;
                return Err(EngineError::InvalidContext);
            }
            if self
                .per_prefix
                .get(&context.prefix_key)
                .copied()
                .unwrap_or(0)
                >= self.config.max_per_prefix
            {
                self.defer(probe)?;
                report.transitions += 1;
                continue;
            }
            let reservation = match sink.try_reserve() {
                Ok(value) => value,
                Err(error) => {
                    self.requeue_front(probe)?;
                    return Err(EngineError::Sink(error));
                }
            };
            match reservation {
                SinkReservation::Saturated => {
                    self.deferred.push_front(probe);
                    self.sink_backpressured = true;
                    report.transitions += 1;
                    break;
                }
                SinkReservation::Reserved => {}
            }
            let purpose = context
                .neighbor_setup
                .map_or(EmissionPurpose::Probe, EmissionPurpose::NeighborSetup);
            if self
                .active
                .insert(
                    probe.logical_id,
                    ActiveProbe {
                        probe,
                        context,
                        stage: ActiveStage::Pending(purpose),
                        stage_transmissions: 0,
                        total_transmissions: 0,
                        last_probe_sent_at: None,
                    },
                )
                .is_some()
            {
                return Err(EngineError::ReservationInvariant);
            }
            increment(&mut self.per_target, probe.target);
            increment(&mut self.per_prefix, context.prefix_key);
            self.context_waiting = false;
            report.transitions += 1;
        }
        Ok(())
    }

    fn emit_pending<T: ProbeTransport, S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        transport: &mut T,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, active)| {
                matches!(
                    active.stage,
                    ActiveStage::Pending(_) | ActiveStage::PendingCleanup(_)
                )
                .then_some(*id)
            })
            .take(remaining)
            .collect();
        for id in ids {
            if report.transitions >= MAX_TRANSITIONS_PER_DRIVE {
                break;
            }
            let Some(active) = self.active.get(&id).copied() else {
                continue;
            };
            let (purpose, terminal) = match active.stage {
                ActiveStage::Pending(purpose) => (purpose, None),
                ActiveStage::PendingCleanup(terminal) => {
                    (EmissionPurpose::TcpResetCleanup, Some(terminal))
                }
                ActiveStage::Waiting { .. } => continue,
            };
            if !self
                .bucket
                .as_mut()
                .ok_or(EngineError::InvalidLifecycle)?
                .try_take(now)?
            {
                break;
            }
            let emission = ProbeEmission {
                probe_id: id,
                probe: active.probe,
                route_generation: active.context.generation,
                purpose,
                transmission: active.stage_transmissions.saturating_add(1),
            };
            let tracked = self
                .active
                .get_mut(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            tracked.total_transmissions = tracked.total_transmissions.saturating_add(1);
            if let Err(error) = transport.emit(emission) {
                if let Some(terminal) = terminal {
                    self.terminalize(id, now, terminal, sink, Some(report))?;
                }
                self.fail_transport(now, error.code, sink, report)?;
                break;
            }
            report.emissions += 1;
            report.transitions += 1;
            if let Some(terminal) = terminal {
                self.terminalize(id, now, terminal, sink, Some(report))?;
                continue;
            }
            let timeout = self.timeout_for(active.stage_transmissions)?;
            let deadline = now
                .checked_add(timeout)
                .ok_or(EngineError::DeadlineOverflow)?;
            let active = self
                .active
                .get_mut(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage_transmissions = active.stage_transmissions.saturating_add(1);
            if purpose == EmissionPurpose::Probe {
                active.last_probe_sent_at = Some(now);
            }
            active.stage = ActiveStage::Waiting { purpose, deadline };
        }
        Ok(())
    }

    fn process_timeouts<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, active)| match active.stage {
                ActiveStage::Waiting { deadline, .. } if now >= deadline => Some(*id),
                _ => None,
            })
            .take(remaining)
            .collect();
        for id in ids {
            if report.transitions >= MAX_TRANSITIONS_PER_DRIVE {
                break;
            }
            self.timeout_one(id, now, sink, report)?;
        }
        Ok(())
    }

    fn timeout_one<S: ResultSink>(
        &mut self,
        id: u64,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let active = self
            .active
            .get(&id)
            .copied()
            .ok_or(EngineError::ReservationInvariant)?;
        let ActiveStage::Waiting { purpose, .. } = active.stage else {
            return Ok(());
        };
        let retries_used = active.stage_transmissions.saturating_sub(1);
        if retries_used < self.config.max_retransmissions {
            let active = self
                .active
                .get_mut(&id)
                .ok_or(EngineError::ReservationInvariant)?;
            active.stage = ActiveStage::Pending(purpose);
            report.transitions += 1;
            return Ok(());
        }
        let terminal = timeout_terminal(active.probe, self.config.discovery_silence);
        self.terminalize(id, now, terminal, sink, Some(report))
    }

    fn terminalize<S: ResultSink>(
        &mut self,
        id: u64,
        now: MonotonicTime,
        terminal: PendingTerminal,
        sink: &mut S,
        report: Option<&mut MutableReport>,
    ) -> Result<(), EngineError> {
        let active = self
            .active
            .get(&id)
            .copied()
            .ok_or(EngineError::ReservationInvariant)?;
        if self.grace.contains_key(&id)
            || self
                .per_target
                .get(&active.probe.target)
                .copied()
                .unwrap_or(0)
                == 0
            || self
                .per_prefix
                .get(&active.context.prefix_key)
                .copied()
                .unwrap_or(0)
                == 0
        {
            return Err(EngineError::ReservationInvariant);
        }
        let expires = now
            .checked_add(self.config.late_grace)
            .ok_or(EngineError::DeadlineOverflow)?;
        let result = ScanResult {
            probe: active.probe,
            outcome: terminal.outcome,
            evidence_strength: terminal.strength,
            attempt: active.probe.attempt,
            transmissions: active.total_transmissions,
            rtt: terminal.rtt,
            terminal_at: now,
            route_generation: active.context.generation,
            terminal_reason: terminal.reason,
        };
        sink.commit_reserved(result).map_err(EngineError::Sink)?;
        if self.active.remove(&id).is_none() {
            return Err(EngineError::ReservationInvariant);
        }
        decrement(&mut self.per_target, active.probe.target)?;
        decrement(&mut self.per_prefix, active.context.prefix_key)?;
        self.grace.insert(id, expires);
        if let Some(report) = report {
            report.results += 1;
            report.transitions += 1;
        }
        Ok(())
    }

    fn initiate_stop(
        &mut self,
        outcome: ProbeOutcome,
        reason: TerminalReason,
        final_lifecycle: SessionLifecycle,
    ) {
        self.cursor = self.plan.logical_probe_count();
        self.deferred.clear();
        self.invalidating_generation = None;
        self.lifecycle = SessionLifecycle::Cancelling;
        self.stop = Some(StopState {
            outcome,
            reason,
            final_lifecycle,
        });
    }

    fn settle_stop<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        let stop = self.stop.ok_or(EngineError::ReservationInvariant)?;
        let remaining = MAX_TRANSITIONS_PER_DRIVE.saturating_sub(report.transitions);
        let ids: Vec<u64> = self.active.keys().copied().take(remaining).collect();
        for id in ids {
            self.terminalize(
                id,
                now,
                PendingTerminal {
                    outcome: stop.outcome,
                    strength: None,
                    rtt: None,
                    reason: stop.reason,
                },
                sink,
                Some(report),
            )?;
        }
        if self.active.is_empty() {
            self.lifecycle = stop.final_lifecycle;
            self.stop = None;
        }
        Ok(())
    }

    fn fail_transport<S: ResultSink>(
        &mut self,
        now: MonotonicTime,
        code: u32,
        sink: &mut S,
        report: &mut MutableReport,
    ) -> Result<(), EngineError> {
        self.initiate_stop(
            ProbeOutcome::TransportFailed,
            TerminalReason::TransportFailure(code),
            SessionLifecycle::Failed,
        );
        self.settle_stop(now, sink, report)
    }

    fn next_candidate(
        &mut self,
        deferred_remaining: &mut usize,
    ) -> Result<Option<LogicalProbe>, EngineError> {
        if *deferred_remaining > 0 {
            *deferred_remaining -= 1;
            return Ok(self.deferred.pop_front());
        }
        if self.cursor >= self.plan.logical_probe_count() {
            return Ok(None);
        }
        let logical_id = self
            .permutation
            .permute(self.cursor)
            .ok_or(EngineError::ReservationInvariant)?;
        self.cursor += 1;
        self.plan
            .logical_probe_at(logical_id)
            .map(Some)
            .map_err(EngineError::Plan)
    }

    fn defer(&mut self, probe: LogicalProbe) -> Result<(), EngineError> {
        if self.deferred.len() == MAX_DEFERRED_CANDIDATES {
            return Err(EngineError::StateCapacityExceeded);
        }
        self.deferred.push_back(probe);
        Ok(())
    }

    fn requeue_front(&mut self, probe: LogicalProbe) -> Result<(), EngineError> {
        if self.deferred.len() == MAX_DEFERRED_CANDIDATES {
            return Err(EngineError::StateCapacityExceeded);
        }
        self.deferred.push_front(probe);
        Ok(())
    }

    fn timeout_for(&self, prior_transmissions: u8) -> Result<ScanDuration, EngineError> {
        let base = self.rtt.timeout(
            self.config.timing_mode,
            self.config.initial_timeout,
            self.config.minimum_timeout,
            self.config.maximum_timeout,
        )?;
        let shift = u32::from(prior_transmissions.min(31));
        Ok(base
            .saturating_mul(1_u32 << shift)
            .min(self.config.maximum_timeout))
    }

    fn observe_now(&mut self, clock: &impl Clock) -> Result<MonotonicTime, EngineError> {
        let now = clock.now();
        if self.last_now.is_some_and(|last| now < last) {
            return Err(EngineError::ClockRegressed);
        }
        self.last_now = Some(now);
        Ok(now)
    }

    fn deadline_reached(&self, now: MonotonicTime) -> bool {
        self.session_deadline
            .is_some_and(|deadline| now >= deadline)
    }

    fn prune_grace(&mut self, now: MonotonicTime) {
        self.grace.retain(|_, expires| now < *expires);
    }

    fn complete_if_finished(&mut self) {
        if self.lifecycle == SessionLifecycle::Running
            && self.cursor == self.plan.logical_probe_count()
            && self.deferred.is_empty()
            && self.active.is_empty()
        {
            self.lifecycle = SessionLifecycle::Completed;
        }
    }

    const fn is_terminal(&self) -> bool {
        matches!(
            self.lifecycle,
            SessionLifecycle::Completed | SessionLifecycle::Failed | SessionLifecycle::Closed
        )
    }

    fn make_report(
        &mut self,
        now: MonotonicTime,
        report: MutableReport,
    ) -> Result<DriveReport, EngineError> {
        if self.is_terminal() {
            return Ok(DriveReport {
                lifecycle: self.lifecycle,
                transitions: report.transitions,
                emissions: report.emissions,
                results: report.results,
                outstanding: self.active.len(),
                deferred: self.deferred.len(),
                grace: self.grace.len(),
                sink_backpressured: self.sink_backpressured,
                context_waiting: self.context_waiting,
                next_wakeup: None,
            });
        }
        let mut next_wakeup = self.session_deadline;
        if self.stop.is_some() || self.invalidating_generation.is_some() {
            next_wakeup = Some(now);
        }
        for active in self.active.values() {
            if let ActiveStage::Waiting { deadline, .. } = active.stage {
                next_wakeup = earlier(next_wakeup, Some(deadline));
            }
        }
        if self.lifecycle == SessionLifecycle::Running {
            next_wakeup = earlier(next_wakeup, self.grace.values().copied().min());
        }
        let has_pending_frame = self.active.values().any(|active| {
            matches!(
                active.stage,
                ActiveStage::Pending(_) | ActiveStage::PendingCleanup(_)
            )
        });
        let can_admit = !self.context_waiting
            && !self.sink_backpressured
            && (self.cursor < self.plan.logical_probe_count() || !self.deferred.is_empty());
        if self.lifecycle == SessionLifecycle::Running && (has_pending_frame || can_admit) {
            let token_ready = self
                .bucket
                .as_mut()
                .ok_or(EngineError::InvalidLifecycle)?
                .next_ready(now)?;
            next_wakeup = earlier(next_wakeup, Some(token_ready));
        }
        Ok(DriveReport {
            lifecycle: self.lifecycle,
            transitions: report.transitions,
            emissions: report.emissions,
            results: report.results,
            outstanding: self.active.len(),
            deferred: self.deferred.len(),
            grace: self.grace.len(),
            sink_backpressured: self.sink_backpressured,
            context_waiting: self.context_waiting,
            next_wakeup,
        })
    }
}

#[derive(Clone, Copy, Default)]
struct MutableReport {
    transitions: usize,
    emissions: usize,
    results: usize,
}

fn classify_terminal(
    probe: LogicalProbe,
    event: EvidenceEvent,
) -> Result<PendingTerminal, EngineError> {
    let state = match probe.family {
        ProbeFamily::TcpSyn => match event.kind {
            EvidenceKind::TcpSynAcknowledgment => NetworkState::Open,
            EvidenceKind::TcpReset => NetworkState::Closed,
            EvidenceKind::IcmpPortUnreachable
            | EvidenceKind::IcmpOtherError
            | EvidenceKind::ExplicitUnreachable => NetworkState::Filtered,
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Udp => match event.kind {
            EvidenceKind::UdpReply => NetworkState::Open,
            EvidenceKind::IcmpPortUnreachable => NetworkState::Closed,
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                NetworkState::Filtered
            }
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Arp => match event.kind {
            EvidenceKind::ArpReply => NetworkState::Up,
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                NetworkState::Unreachable
            }
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Ndp => match event.kind {
            EvidenceKind::NeighborAdvertisement => NetworkState::Up,
            EvidenceKind::IcmpOtherError | EvidenceKind::ExplicitUnreachable => {
                NetworkState::Unreachable
            }
            _ => return Err(EngineError::InvalidEvidence),
        },
        ProbeFamily::Icmpv4Echo | ProbeFamily::Icmpv6Echo => match event.kind {
            EvidenceKind::EchoReply => NetworkState::Up,
            EvidenceKind::IcmpPortUnreachable
            | EvidenceKind::IcmpOtherError
            | EvidenceKind::ExplicitUnreachable => NetworkState::Unreachable,
            _ => return Err(EngineError::InvalidEvidence),
        },
    };
    Ok(PendingTerminal {
        outcome: ProbeOutcome::Network(state),
        strength: Some(event.strength),
        rtt: None,
        reason: TerminalReason::Evidence(event.kind),
    })
}

const fn valid_neighbor_setup(probe: LogicalProbe, setup: Option<ProbeFamily>) -> bool {
    match (probe.target.address, setup) {
        (_, None)
        | (nodenet_protocols::IpAddress::V4(_), Some(ProbeFamily::Arp))
        | (nodenet_protocols::IpAddress::V6(_), Some(ProbeFamily::Ndp)) => true,
        (nodenet_protocols::IpAddress::V4(_) | nodenet_protocols::IpAddress::V6(_), Some(_)) => {
            false
        }
    }
}

const fn valid_neighbor_evidence(setup: ProbeFamily, kind: EvidenceKind) -> bool {
    matches!(kind, EvidenceKind::NeighborResolved)
        || matches!(
            (setup, kind),
            (ProbeFamily::Arp, EvidenceKind::ArpReply)
                | (ProbeFamily::Ndp, EvidenceKind::NeighborAdvertisement)
        )
}

const fn timeout_terminal(
    probe: LogicalProbe,
    discovery_policy: DiscoverySilencePolicy,
) -> PendingTerminal {
    let state = match probe.family {
        ProbeFamily::TcpSyn => NetworkState::Filtered,
        ProbeFamily::Udp => NetworkState::OpenOrFiltered,
        ProbeFamily::Arp | ProbeFamily::Ndp | ProbeFamily::Icmpv4Echo | ProbeFamily::Icmpv6Echo => {
            match discovery_policy {
                DiscoverySilencePolicy::Unknown => NetworkState::Unknown,
                DiscoverySilencePolicy::DownByPolicy => NetworkState::DownByPolicy,
            }
        }
    };
    PendingTerminal {
        outcome: ProbeOutcome::Network(state),
        strength: None,
        rtt: None,
        reason: TerminalReason::Timeout,
    }
}

fn increment<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) {
    *counts.entry(key).or_insert(0) += 1;
}

fn decrement<K: Ord + Copy>(counts: &mut BTreeMap<K, usize>, key: K) -> Result<(), EngineError> {
    let value = counts
        .get_mut(&key)
        .ok_or(EngineError::ReservationInvariant)?;
    *value = value
        .checked_sub(1)
        .ok_or(EngineError::ReservationInvariant)?;
    if *value == 0 {
        counts.remove(&key);
    }
    Ok(())
}

const fn earlier(
    left: Option<MonotonicTime>,
    right: Option<MonotonicTime>,
) -> Option<MonotonicTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left.as_micros() <= right.as_micros() {
            left
        } else {
            right
        }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}
