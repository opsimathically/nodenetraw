use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use nodenet_linux_context::{
    NetworkSnapshot, RouteContext, RouteDisposition, RoutePlanKind, RouteQuery,
};
use nodenet_protocols::{EvidenceStrength, ProbePort};
use nodenetscanner_engine::{
    Clock, ContextFailure, ContextResolution, ContextResolver, LogicalProbe, MonotonicTime,
    NetworkState, PrefixKey, ProbeEmission, ProbeFamily, ProbeOutcome, ProbeTransport,
    ResolvedContext, ResultSink, ScanResult, ScanScheduler, SchedulingSeed, SeededPermutation,
    SessionLifecycle, SinkFailure, SinkReservation, TerminalReason, TransportFailure,
};

use crate::error::ScannerError;
use crate::model::{ValidatedPlan, to_std_address};
use crate::socket::PortableSockets;
use crate::wire::{RouteBinding, WireState};

const MAX_QUEUED_RESULTS: usize = 262_144;
const MAX_RECEIVES_PER_TICK: usize = 128;
const RESULT_BATCH_SCHEMA_VERSION: u32 = 1;
const MISSING_U64: u64 = u64::MAX;

#[napi(object)]
pub struct NativeScanResultBatch {
    pub schema_version: u32,
    pub row_count: u32,
    pub byte_order: String,
    pub address_bytes: Buffer,
    pub address_offsets: Buffer,
    pub families: Buffer,
    pub scopes: Buffer,
    pub probes: Buffer,
    pub ports: Buffer,
    pub states: Buffer,
    pub outcomes: Buffer,
    pub attempts: Buffer,
    pub transmissions: Buffer,
    pub rtt_nanoseconds: Buffer,
    pub timestamps_nanoseconds: Buffer,
    pub route_generations: Buffer,
    pub evidence: Buffer,
    pub metadata_bytes: Buffer,
    pub metadata_offsets: Buffer,
}

pub struct SealedScanResultBatch {
    pub schema_version: u32,
    pub row_count: u32,
    pub address_bytes: Vec<u8>,
    pub address_offsets: Vec<u8>,
    pub families: Vec<u8>,
    pub scopes: Vec<u8>,
    pub probes: Vec<u8>,
    pub ports: Vec<u8>,
    pub states: Vec<u8>,
    pub outcomes: Vec<u8>,
    pub attempts: Vec<u8>,
    pub transmissions: Vec<u8>,
    pub rtt_nanoseconds: Vec<u8>,
    pub timestamps_nanoseconds: Vec<u8>,
    pub route_generations: Vec<u8>,
    pub evidence: Vec<u8>,
    pub metadata_bytes: Vec<u8>,
    pub metadata_offsets: Vec<u8>,
}

impl NativeScanResultBatch {
    pub(crate) fn from_sealed(value: SealedScanResultBatch) -> Self {
        Self {
            schema_version: value.schema_version,
            row_count: value.row_count,
            byte_order: "little-endian".into(),
            address_bytes: value.address_bytes.into(),
            address_offsets: value.address_offsets.into(),
            families: value.families.into(),
            scopes: value.scopes.into(),
            probes: value.probes.into(),
            ports: value.ports.into(),
            states: value.states.into(),
            outcomes: value.outcomes.into(),
            attempts: value.attempts.into(),
            transmissions: value.transmissions.into(),
            rtt_nanoseconds: value.rtt_nanoseconds.into(),
            timestamps_nanoseconds: value.timestamps_nanoseconds.into(),
            route_generations: value.route_generations.into(),
            evidence: value.evidence.into(),
            metadata_bytes: value.metadata_bytes.into(),
            metadata_offsets: value.metadata_offsets.into(),
        }
    }
}

#[napi(object)]
pub struct NativePullResult {
    pub status: String,
    pub batch: Option<NativeScanResultBatch>,
}

impl NativePullResult {
    pub(crate) fn from_pull(value: PullResult) -> Self {
        match value {
            PullResult::Batch(batch) => Self {
                status: "batch".into(),
                batch: Some(NativeScanResultBatch::from_sealed(*batch)),
            },
            PullResult::Terminal => Self {
                status: "terminal".into(),
                batch: None,
            },
            PullResult::Aborted => Self {
                status: "aborted".into(),
                batch: None,
            },
        }
    }
}

pub enum PullResult {
    Batch(Box<SealedScanResultBatch>),
    Terminal,
    Aborted,
}

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NativeScanProgress {
    pub sent: String,
    pub received: String,
    pub matched: String,
    pub duplicate: String,
    pub invalid: String,
    pub timed_out: String,
    pub retried: String,
    pub kernel_dropped: String,
    pub application_backpressured: String,
    pub coalesced_updates: String,
}

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NativeScanSummary {
    pub state: String,
    pub logical_probes: String,
    pub results: String,
    pub open: String,
    pub closed: String,
    pub filtered: String,
    pub open_or_filtered: String,
    pub up: String,
    pub unreachable: String,
    pub unknown: String,
    pub cancelled: String,
    pub deadline: String,
    pub discarded: String,
    pub kernel_dropped: String,
    pub forged_or_unrelated: String,
    pub duplicates: String,
    pub late_responses: String,
    pub progress: NativeScanProgress,
    pub scheduling_seed: Option<String>,
    pub accuracy_tradeoff: bool,
    pub error: Option<NativeScanFailure>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeScanFailure {
    pub kind: String,
    pub code: String,
    pub operation: String,
    pub errno: Option<i32>,
    pub message: String,
}

#[derive(Default)]
struct SummaryCounters {
    results: u64,
    open: u64,
    closed: u64,
    filtered: u64,
    open_or_filtered: u64,
    up: u64,
    unreachable: u64,
    unknown: u64,
    cancelled: u64,
    deadline: u64,
    discarded: u64,
    timed_out: u64,
}

struct ResultQueue {
    capacity: usize,
    low_watermark: usize,
    reserved: usize,
    backpressured: bool,
    application_backpressured: u64,
    values: VecDeque<ScanResult>,
    completed_ids: VecDeque<u64>,
    counters: SummaryCounters,
}

impl ResultQueue {
    fn new(logical_probes: u64) -> Self {
        let capacity = usize::try_from(logical_probes)
            .unwrap_or(MAX_QUEUED_RESULTS)
            .clamp(1, MAX_QUEUED_RESULTS);
        Self {
            capacity,
            low_watermark: capacity / 2,
            reserved: 0,
            backpressured: false,
            application_backpressured: 0,
            values: VecDeque::new(),
            completed_ids: VecDeque::new(),
            counters: SummaryCounters::default(),
        }
    }

    fn take(&mut self, maximum: usize) -> Option<SealedScanResultBatch> {
        if self.values.is_empty() {
            return None;
        }
        let count = maximum.min(self.values.len());
        let values = self.values.drain(..count);
        Some(seal_result_batch(values, count))
    }

    fn discard(&mut self) -> u64 {
        let count = u64::try_from(self.values.len()).unwrap_or(u64::MAX);
        self.values.clear();
        self.counters.discarded = self.counters.discarded.saturating_add(count);
        count
    }

    fn take_completed_ids(&mut self) -> Vec<u64> {
        self.completed_ids.drain(..).collect()
    }
}

impl ResultSink for ResultQueue {
    fn try_reserve(&mut self) -> Result<SinkReservation, SinkFailure> {
        let occupancy = self.values.len().saturating_add(self.reserved);
        if self.backpressured {
            if occupancy > self.low_watermark {
                return Ok(SinkReservation::Saturated);
            }
            self.backpressured = false;
        }
        if occupancy >= self.capacity {
            self.backpressured = true;
            self.application_backpressured = self.application_backpressured.saturating_add(1);
            return Ok(SinkReservation::Saturated);
        }
        self.reserved += 1;
        Ok(SinkReservation::Reserved)
    }

    fn commit_reserved(&mut self, result: ScanResult) -> Result<(), SinkFailure> {
        if self.reserved == 0 || self.values.len() >= self.capacity {
            return Err(SinkFailure { code: 1 });
        }
        self.reserved -= 1;
        self.completed_ids.push_back(result.probe.logical_id);
        count_result(&mut self.counters, result);
        self.values.push_back(result);
        Ok(())
    }

    fn release_reserved(&mut self, count: usize) -> Result<(), SinkFailure> {
        if count > self.reserved {
            return Err(SinkFailure { code: 2 });
        }
        self.reserved -= count;
        Ok(())
    }
}

struct SessionClock {
    origin: Instant,
}

impl Clock for SessionClock {
    fn now(&self) -> MonotonicTime {
        let micros = self.origin.elapsed().as_micros();
        MonotonicTime::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }
}

struct SocketNetwork {
    sockets: PortableSockets,
    wire: WireState,
    last_error: Option<ScannerError>,
}

struct TransportAdapter {
    network: Arc<Mutex<SocketNetwork>>,
}

impl ProbeTransport for TransportAdapter {
    fn emit(&mut self, emission: ProbeEmission) -> Result<(), TransportFailure> {
        let mut network = lock(&self.network);
        let SocketNetwork { sockets, wire, .. } = &mut *network;
        if let Err(error) = wire.emit(sockets, emission) {
            network.last_error = Some(error);
            return Err(TransportFailure { code: 1 });
        }
        Ok(())
    }
}

struct ResolverAdapter<'a> {
    context: &'a mut RouteContext,
    network: Arc<Mutex<SocketNetwork>>,
    interface: Option<&'a str>,
    source: Option<IpAddr>,
}

impl ContextResolver for ResolverAdapter<'_> {
    fn resolve(&mut self, probe: LogicalProbe) -> Result<ContextResolution, ContextFailure> {
        if lock(&self.network).wire.has_route(probe.logical_id) {
            let generation = lock(&self.network)
                .wire_generation(probe.logical_id)
                .unwrap_or_default();
            return Ok(ContextResolution::Ready(ResolvedContext {
                generation,
                prefix_key: PrefixKey::default_for(probe.target),
                neighbor_setup: None,
            }));
        }
        match self.resolve_inner(probe) {
            Ok(value) => Ok(value),
            Err(error) => {
                lock(&self.network).last_error = Some(error);
                Err(ContextFailure { code: 1 })
            }
        }
    }
}

impl ResolverAdapter<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "route policy joins generation, source, link, and neighbor decisions atomically"
    )]
    fn resolve_inner(&mut self, probe: LogicalProbe) -> Result<ContextResolution, ScannerError> {
        let snapshot =
            self.context.current_snapshot().cloned().ok_or_else(|| {
                ScannerError::context("resolve route", "network context unavailable")
            })?;
        let destination = to_std_address(probe.target.address);
        let interface_index = match (self.interface, probe.target.scope) {
            (Some(name), _) => Some(
                snapshot
                    .interfaces
                    .iter()
                    .find(|value| value.name == name)
                    .map(|value| value.index)
                    .ok_or_else(|| {
                        ScannerError::invalid("resolve route", "interface override was not found")
                    })?,
            ),
            (None, Some(scope)) => Some(scope.get()),
            (None, None) => None,
        };
        let mut query = RouteQuery::new(destination);
        query.source = self.source;
        query.output_interface = interface_index;
        let plan = self
            .context
            .resolve_route(&query, None)
            .map_err(|error| ScannerError::context("resolve route", error.to_string()))?;
        let kind = match plan.disposition {
            RouteDisposition::Usable(value) => value,
            RouteDisposition::Unusable(reason) => {
                return Err(ScannerError::unsupported(
                    "resolve route",
                    format!("route is unusable: {reason:?}"),
                ));
            }
            RouteDisposition::Unsupported(reason) => {
                return Err(ScannerError::unsupported(
                    "resolve route",
                    format!("route is unsupported: {reason:?}"),
                ));
            }
        };
        let interface_index = plan.interface_index.ok_or_else(|| {
            ScannerError::unsupported("resolve route", "route has no output interface")
        })?;
        let source = self
            .source
            .or(plan.preferred_source)
            .or_else(|| select_source(&snapshot, interface_index, destination))
            .ok_or_else(|| {
                ScannerError::unsupported("resolve route", "route has no usable source address")
            })?;
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(ScannerError::invalid(
                "resolve route",
                "source and destination families differ",
            ));
        }
        let next_hop = plan.next_hop.unwrap_or(destination);
        if matches!(probe.family, ProbeFamily::Arp | ProbeFamily::Ndp)
            && kind != RoutePlanKind::EthernetOnLink
        {
            return Err(ScannerError::unsupported(
                "resolve discovery route",
                "ARP/NDP targets must be directly on-link Ethernet neighbors",
            ));
        }
        let interface = snapshot
            .interfaces
            .iter()
            .find(|value| value.index == interface_index)
            .ok_or_else(|| ScannerError::context("resolve route", "interface record missing"))?;
        let source_mac = six_bytes(&interface.hardware_address);
        let mut destination_mac = plan.link_layer_address.as_deref().and_then(six_bytes);
        if destination_mac.is_none() && kind == RoutePlanKind::Multicast {
            destination_mac = multicast_mac(destination);
        }
        let neighbor_setup = if destination_mac.is_none()
            && matches!(
                kind,
                RoutePlanKind::EthernetOnLink | RoutePlanKind::EthernetGateway
            )
            && !matches!(probe.family, ProbeFamily::Arp | ProbeFamily::Ndp)
        {
            Some(if destination.is_ipv4() {
                ProbeFamily::Arp
            } else {
                ProbeFamily::Ndp
            })
        } else {
            None
        };
        let generation = plan.generation;
        lock(&self.network).wire.insert_route(
            probe.logical_id,
            RouteBinding {
                generation,
                kind,
                interface_index,
                source,
                destination,
                next_hop,
                source_mac,
                destination_mac,
            },
        );
        Ok(ContextResolution::Ready(ResolvedContext {
            generation,
            prefix_key: PrefixKey::default_for(probe.target),
            neighbor_setup,
        }))
    }
}

impl SocketNetwork {
    fn wire_generation(&self, probe_id: u64) -> Option<u64> {
        self.wire.generation(probe_id)
    }
}

pub(crate) struct SessionCore {
    pub scanner_id: u32,
    scheduler: ScanScheduler,
    clock: SessionClock,
    network: Option<Arc<Mutex<SocketNetwork>>>,
    results: ResultQueue,
    logical_probes: u64,
    interface: Option<String>,
    source: Option<IpAddr>,
    kernel_dropped: u64,
    received: u64,
    matched: u64,
    wire_sent: u64,
    wire_invalid: u64,
    wire_retried: u64,
    terminal_error: Option<ScannerError>,
    context_changed: bool,
}

impl SessionCore {
    pub(crate) fn new(
        _id: u32,
        scanner_id: u32,
        slot: u8,
        validated: ValidatedPlan,
        context: &mut RouteContext,
    ) -> Result<Self, ScannerError> {
        if context.current_snapshot().is_none() {
            context.snapshot().map_err(|error| {
                ScannerError::context("capture network context", error.to_string())
            })?;
        }
        let port_span =
            usize::from(validated.options.source_port_end - validated.options.source_port_start)
                + 1;
        let per_session_ports = port_span / 4;
        if validated.scheduler.max_outstanding > per_session_ports {
            return Err(ScannerError::invalid(
                "validate source port range",
                "source port range provides fewer collision-free ports than maxOutstanding across four sessions",
            ));
        }
        let secret = read_secret()?;
        let sockets = PortableSockets::open()?;
        let seed = if validated.options.seed == 0 {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&secret[..8]);
            u64::from_ne_bytes(bytes)
        } else {
            validated.options.seed
        };
        let logical_probes = validated.plan.logical_probe_count();
        let permutation = SeededPermutation::new(
            logical_probes,
            if validated.options.seed == 0 {
                SchedulingSeed::Generated {
                    value: seed,
                    report: false,
                }
            } else {
                SchedulingSeed::Explicit(seed)
            },
        )?;
        let mut scheduler = ScanScheduler::new(validated.plan, validated.scheduler, permutation)?;
        let clock = SessionClock {
            origin: Instant::now(),
        };
        scheduler.start(&clock)?;
        let interface = validated.options.interface.clone();
        let source = validated.options.source_address;
        Ok(Self {
            scanner_id,
            scheduler,
            clock,
            network: Some(Arc::new(Mutex::new(SocketNetwork {
                sockets,
                wire: WireState::new(secret, slot, validated.options),
                last_error: None,
            }))),
            results: ResultQueue::new(logical_probes),
            logical_probes,
            interface,
            source,
            kernel_dropped: 0,
            received: 0,
            matched: 0,
            wire_sent: 0,
            wire_invalid: 0,
            wire_retried: 0,
            terminal_error: None,
            context_changed: false,
        })
    }

    pub(crate) fn lifecycle(&self) -> SessionLifecycle {
        self.scheduler.lifecycle()
    }

    pub(crate) fn drive(&mut self, context: &mut RouteContext) {
        let Some(network) = self.network.clone() else {
            return;
        };
        self.receive(&network);
        self.sync_terminal_correlations(&network);
        if self.context_changed {
            self.scheduler.context_restored();
        }
        let mut transport = TransportAdapter {
            network: Arc::clone(&network),
        };
        let mut resolver = ResolverAdapter {
            context,
            network: Arc::clone(&network),
            interface: self.interface.as_deref(),
            source: self.source,
        };
        let result = self.scheduler.drive(
            &self.clock,
            &mut transport,
            &mut resolver,
            &mut self.results,
        );
        if let Err(error) = result {
            self.fail(error.to_string(), &network);
        }
        self.sync_terminal_correlations(&network);
        self.receive(&network);
        self.sync_terminal_correlations(&network);
        if is_terminal(self.scheduler.lifecycle()) {
            self.finish_network();
        }
    }

    fn receive(&mut self, network: &Arc<Mutex<SocketNetwork>>) {
        for _ in 0..MAX_RECEIVES_PER_TICK {
            let observations = {
                let mut state = lock(network);
                match state.sockets.receive_packet() {
                    Ok(Some(message)) => {
                        self.received = self.received.saturating_add(1);
                        state.wire.process_packet(&message)
                    }
                    Ok(None) => match state.sockets.receive_raw() {
                        Ok(Some(message)) => {
                            self.received = self.received.saturating_add(1);
                            state.wire.process_raw(&message)
                        }
                        Ok(None) => break,
                        Err(error) => {
                            state.last_error = Some(error);
                            break;
                        }
                    },
                    Err(error) => {
                        state.last_error = Some(error);
                        break;
                    }
                }
            };
            self.matched = self
                .matched
                .saturating_add(u64::try_from(observations.len()).unwrap_or(u64::MAX));
            for observation in observations {
                let mut transport = TransportAdapter {
                    network: Arc::clone(network),
                };
                if let Err(error) = self.scheduler.handle_evidence(
                    &self.clock,
                    observation.event,
                    &mut transport,
                    &mut self.results,
                ) {
                    self.fail(error.to_string(), network);
                    return;
                }
            }
        }
        if let Some(error) = lock(network).last_error.take() {
            self.terminal_error = Some(error);
            if let Err(error) = self
                .scheduler
                .transport_failed(&self.clock, 1, &mut self.results)
            {
                self.terminal_error = Some(ScannerError::internal(
                    "settle receive failure",
                    error.to_string(),
                ));
            }
        }
    }

    fn fail(&mut self, message: String, network: &Arc<Mutex<SocketNetwork>>) {
        self.terminal_error = lock(network)
            .last_error
            .take()
            .or_else(|| Some(ScannerError::internal("drive scanner", message)));
        let result =
            if self.terminal_error.as_ref().is_some_and(|error| {
                matches!(error.kind, "context" | "unsupported" | "invalidPlan")
            }) {
                self.scheduler
                    .context_failed(&self.clock, &mut self.results)
            } else {
                self.scheduler
                    .transport_failed(&self.clock, 1, &mut self.results)
            };
        if let Err(error) = result {
            self.terminal_error = Some(ScannerError::internal(
                "settle scanner failure",
                error.to_string(),
            ));
        }
        self.sync_terminal_correlations(network);
    }

    fn sync_terminal_correlations(&mut self, network: &Arc<Mutex<SocketNetwork>>) {
        let completed = self.results.take_completed_ids();
        let mut network = lock(network);
        if completed.is_empty() {
            network.wire.prune_terminal();
        } else {
            network.wire.mark_terminal(completed);
        }
    }

    pub(crate) fn invalidate_context(&mut self) {
        if is_terminal(self.scheduler.lifecycle()) {
            return;
        }
        if let Err(error) = self
            .scheduler
            .invalidate_context(&self.clock, None, &mut self.results)
        {
            self.terminal_error = Some(ScannerError::context(
                "invalidate scan context",
                error.to_string(),
            ));
        }
        self.context_changed = true;
        if let Some(network) = self.network.clone() {
            self.sync_terminal_correlations(&network);
        }
    }

    pub(crate) fn fail_context(&mut self, error: ScannerError) {
        if is_terminal(self.scheduler.lifecycle()) {
            return;
        }
        self.terminal_error = Some(error);
        if let Err(error) = self
            .scheduler
            .context_failed(&self.clock, &mut self.results)
        {
            self.terminal_error = Some(ScannerError::internal(
                "settle context failure",
                error.to_string(),
            ));
        }
        if let Some(network) = self.network.clone() {
            self.sync_terminal_correlations(&network);
        }
    }

    fn finish_network(&mut self) {
        if let Some(network) = self.network.take() {
            let mut network = lock(&network);
            self.sample_kernel_drops(&mut network);
            let progress = network.wire.progress();
            self.wire_sent = progress.sent;
            self.wire_invalid = progress.invalid;
            self.wire_retried = progress.retried;
        }
    }

    pub(crate) fn request_pause(&mut self) -> Result<(), ScannerError> {
        self.scheduler.request_pause().map_err(ScannerError::from)
    }

    pub(crate) fn resume(&mut self) -> Result<(), ScannerError> {
        self.scheduler.resume().map_err(ScannerError::from)
    }

    pub(crate) fn cancel(&mut self) -> Result<(), ScannerError> {
        if is_terminal(self.scheduler.lifecycle()) {
            return Ok(());
        }
        self.scheduler
            .cancel(&self.clock, &mut self.results)
            .map_err(ScannerError::from)
    }

    pub(crate) fn next_batch(&mut self, maximum: usize) -> Option<SealedScanResultBatch> {
        self.results.take(maximum)
    }

    pub(crate) fn queued_results(&self) -> usize {
        self.results.values.len()
    }

    pub(crate) fn close(&mut self) {
        self.results.discard();
        let _ = self.scheduler.close(&mut self.results);
        self.finish_network();
    }

    pub(crate) fn summary(&self) -> NativeScanSummary {
        let diagnostics = self.scheduler.diagnostics();
        let counters = &self.results.counters;
        NativeScanSummary {
            state: state_name(self.scheduler.lifecycle()).into(),
            logical_probes: self.logical_probes.to_string(),
            results: counters.results.to_string(),
            open: counters.open.to_string(),
            closed: counters.closed.to_string(),
            filtered: counters.filtered.to_string(),
            open_or_filtered: counters.open_or_filtered.to_string(),
            up: counters.up.to_string(),
            unreachable: counters.unreachable.to_string(),
            unknown: counters.unknown.to_string(),
            cancelled: counters.cancelled.to_string(),
            deadline: counters.deadline.to_string(),
            discarded: counters.discarded.to_string(),
            kernel_dropped: self.kernel_dropped.to_string(),
            forged_or_unrelated: diagnostics.forged_or_unrelated.to_string(),
            duplicates: diagnostics.duplicates.to_string(),
            late_responses: diagnostics.late_responses.to_string(),
            progress: self.progress_snapshot(),
            scheduling_seed: self
                .scheduler
                .reported_seed()
                .map(|value| value.to_string()),
            accuracy_tradeoff: self.scheduler.accuracy_tradeoff_reported(),
            error: self.terminal_error.as_ref().map(native_failure),
        }
    }

    pub(crate) fn progress(&mut self) -> NativeScanProgress {
        if let Some(network) = self.network.clone() {
            self.sample_kernel_drops(&mut lock(&network));
        }
        self.progress_snapshot()
    }

    fn progress_snapshot(&self) -> NativeScanProgress {
        let diagnostics = self.scheduler.diagnostics();
        let live_wire = self
            .network
            .as_ref()
            .map(|network| lock(network).wire.progress());
        let sent = live_wire.map_or(self.wire_sent, |value| value.sent);
        let wire_invalid = live_wire.map_or(self.wire_invalid, |value| value.invalid);
        let retried = live_wire.map_or(self.wire_retried, |value| value.retried);
        let invalid = wire_invalid
            .saturating_add(diagnostics.forged_or_unrelated)
            .saturating_add(diagnostics.non_first_fragment)
            .saturating_add(diagnostics.opaque_protocol)
            .saturating_add(diagnostics.insufficient_quote);
        let updates = sent
            .saturating_add(self.received)
            .saturating_add(self.matched)
            .saturating_add(diagnostics.duplicates)
            .saturating_add(invalid)
            .saturating_add(self.results.counters.timed_out)
            .saturating_add(retried)
            .saturating_add(self.kernel_dropped)
            .saturating_add(self.results.application_backpressured);
        NativeScanProgress {
            sent: sent.to_string(),
            received: self.received.to_string(),
            matched: self.matched.to_string(),
            duplicate: diagnostics.duplicates.to_string(),
            invalid: invalid.to_string(),
            timed_out: self.results.counters.timed_out.to_string(),
            retried: retried.to_string(),
            kernel_dropped: self.kernel_dropped.to_string(),
            application_backpressured: self.results.application_backpressured.to_string(),
            coalesced_updates: updates.saturating_sub(1).to_string(),
        }
    }

    fn sample_kernel_drops(&mut self, network: &mut SocketNetwork) {
        self.kernel_dropped = self
            .kernel_dropped
            .saturating_add(network.sockets.take_packet_drops().unwrap_or_default());
    }
}

fn native_failure(error: &ScannerError) -> NativeScanFailure {
    NativeScanFailure {
        kind: error.kind.into(),
        code: error.code.into(),
        operation: error.operation.into(),
        errno: error.errno,
        message: error.message.clone(),
    }
}

fn read_secret() -> Result<[u8; 32], ScannerError> {
    let mut file = File::open("/dev/urandom")
        .map_err(|error| ScannerError::internal("read session entropy", error.to_string()))?;
    let mut bytes = [0_u8; 32];
    file.read_exact(&mut bytes)
        .map_err(|error| ScannerError::internal("read session entropy", error.to_string()))?;
    Ok(bytes)
}

fn select_source(
    snapshot: &NetworkSnapshot,
    interface_index: u32,
    destination: IpAddr,
) -> Option<IpAddr> {
    snapshot.addresses.iter().find_map(|record| {
        if record.interface_index != interface_index {
            return None;
        }
        record
            .local
            .or(record.address)
            .filter(|value| value.is_ipv4() == destination.is_ipv4() && !value.is_unspecified())
    })
}

fn six_bytes(value: &[u8]) -> Option<[u8; 6]> {
    value.try_into().ok()
}

fn multicast_mac(destination: IpAddr) -> Option<[u8; 6]> {
    match destination {
        IpAddr::V4(value) if value.is_multicast() => {
            let octets = value.octets();
            Some([0x01, 0x00, 0x5e, octets[1] & 0x7f, octets[2], octets[3]])
        }
        IpAddr::V6(value) if value.is_multicast() => {
            let octets = value.octets();
            Some([0x33, 0x33, octets[12], octets[13], octets[14], octets[15]])
        }
        _ => None,
    }
}

fn is_terminal(value: SessionLifecycle) -> bool {
    matches!(
        value,
        SessionLifecycle::Completed | SessionLifecycle::Failed | SessionLifecycle::Closed
    )
}

pub(crate) fn state_name(value: SessionLifecycle) -> &'static str {
    match value {
        SessionLifecycle::Created => "created",
        SessionLifecycle::Running => "running",
        SessionLifecycle::Pausing => "pausing",
        SessionLifecycle::Paused => "paused",
        SessionLifecycle::Cancelling => "cancelling",
        SessionLifecycle::Completed => "completed",
        SessionLifecycle::Failed => "failed",
        SessionLifecycle::Closed => "closed",
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the versioned columnar schema is sealed in one auditable encoding transaction"
)]
fn seal_result_batch(
    values: impl Iterator<Item = ScanResult>,
    count: usize,
) -> SealedScanResultBatch {
    let mut address_bytes = Vec::with_capacity(count.saturating_mul(16));
    let mut address_offsets = Vec::with_capacity((count + 1).saturating_mul(4));
    let mut families = Vec::with_capacity(count);
    let mut scopes = Vec::with_capacity(count.saturating_mul(4));
    let mut probes = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count.saturating_mul(2));
    let mut states = Vec::with_capacity(count);
    let mut outcomes = Vec::with_capacity(count);
    let mut attempts = Vec::with_capacity(count.saturating_mul(4));
    let mut transmissions = Vec::with_capacity(count.saturating_mul(4));
    let mut rtt_nanoseconds = Vec::with_capacity(count.saturating_mul(8));
    let mut timestamps_nanoseconds = Vec::with_capacity(count.saturating_mul(8));
    let mut route_generations = Vec::with_capacity(count.saturating_mul(8));
    let mut evidence = Vec::with_capacity(count);
    let mut metadata_bytes = Vec::with_capacity(count.saturating_mul(32));
    let mut metadata_offsets = Vec::with_capacity((count + 1).saturating_mul(4));
    push_u32(&mut address_offsets, 0);
    push_u32(&mut metadata_offsets, 0);

    for value in values {
        match value.probe.target.address {
            nodenet_protocols::IpAddress::V4(address) => {
                families.push(4);
                address_bytes.extend_from_slice(&address.octets());
            }
            nodenet_protocols::IpAddress::V6(address) => {
                families.push(6);
                address_bytes.extend_from_slice(&address.octets());
            }
        }
        push_u32(
            &mut address_offsets,
            u32::try_from(address_bytes.len()).unwrap_or(u32::MAX),
        );
        push_u32(
            &mut scopes,
            value
                .probe
                .target
                .scope
                .map_or(0, nodenetscanner_engine::TargetScope::get),
        );
        probes.push(probe_code(value.probe.family));
        push_u16(&mut ports, value.probe.port.map_or(0, ProbePort::get));
        states.push(match value.outcome {
            ProbeOutcome::Network(state) => network_state_code(state),
            _ => 0,
        });
        outcomes.push(outcome_code(value.outcome));
        push_u32(&mut attempts, value.attempt);
        push_u32(&mut transmissions, u32::from(value.transmissions));
        push_u64(
            &mut rtt_nanoseconds,
            value.rtt.map_or(MISSING_U64, |duration| {
                duration.as_micros().saturating_mul(1_000)
            }),
        );
        push_u64(
            &mut timestamps_nanoseconds,
            value.terminal_at.as_micros().saturating_mul(1_000),
        );
        push_u64(&mut route_generations, value.route_generation);
        evidence.push(value.evidence_strength.map_or(0, evidence_code));
        metadata_bytes.extend_from_slice(reason_name(value.terminal_reason).as_bytes());
        push_u32(
            &mut metadata_offsets,
            u32::try_from(metadata_bytes.len()).unwrap_or(u32::MAX),
        );
    }

    SealedScanResultBatch {
        schema_version: RESULT_BATCH_SCHEMA_VERSION,
        row_count: u32::try_from(count).unwrap_or(u32::MAX),
        address_bytes,
        address_offsets,
        families,
        scopes,
        probes,
        ports,
        states,
        outcomes,
        attempts,
        transmissions,
        rtt_nanoseconds,
        timestamps_nanoseconds,
        route_generations,
        evidence,
        metadata_bytes,
        metadata_offsets,
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

const fn probe_code(value: ProbeFamily) -> u8 {
    match value {
        ProbeFamily::Arp => 1,
        ProbeFamily::Ndp => 2,
        ProbeFamily::Icmpv4Echo => 3,
        ProbeFamily::Icmpv6Echo => 4,
        ProbeFamily::TcpSyn => 5,
        ProbeFamily::Udp => 6,
    }
}

const fn network_state_code(value: NetworkState) -> u8 {
    match value {
        NetworkState::Open => 1,
        NetworkState::Closed => 2,
        NetworkState::Filtered => 3,
        NetworkState::OpenOrFiltered => 4,
        NetworkState::Up => 5,
        NetworkState::Unreachable => 6,
        NetworkState::Unknown => 7,
        NetworkState::DownByPolicy => 8,
    }
}

const fn outcome_code(value: ProbeOutcome) -> u8 {
    match value {
        ProbeOutcome::Network(_) => 1,
        ProbeOutcome::Cancelled => 2,
        ProbeOutcome::SessionDeadline => 3,
        ProbeOutcome::TransportFailed => 4,
        ProbeOutcome::ContextInvalidated => 5,
    }
}

const fn evidence_code(value: EvidenceStrength) -> u8 {
    match value {
        EvidenceStrength::TupleCorrelatedUnauthenticated => 1,
        EvidenceStrength::TruncatedQuote => 2,
        EvidenceStrength::StrongTcpSequence32 => 3,
        EvidenceStrength::StrongPayload128 => 4,
    }
}

fn count_result(counters: &mut SummaryCounters, value: ScanResult) {
    counters.results = counters.results.saturating_add(1);
    if value.terminal_reason == TerminalReason::Timeout {
        counters.timed_out = counters.timed_out.saturating_add(1);
    }
    match value.outcome {
        ProbeOutcome::Network(NetworkState::Open) => {
            counters.open = counters.open.saturating_add(1);
        }
        ProbeOutcome::Network(NetworkState::Closed) => {
            counters.closed = counters.closed.saturating_add(1);
        }
        ProbeOutcome::Network(NetworkState::Filtered) => {
            counters.filtered = counters.filtered.saturating_add(1);
        }
        ProbeOutcome::Network(NetworkState::OpenOrFiltered) => {
            counters.open_or_filtered = counters.open_or_filtered.saturating_add(1);
        }
        ProbeOutcome::Network(NetworkState::Up) => counters.up = counters.up.saturating_add(1),
        ProbeOutcome::Network(NetworkState::Unreachable) => {
            counters.unreachable = counters.unreachable.saturating_add(1);
        }
        ProbeOutcome::Network(NetworkState::Unknown | NetworkState::DownByPolicy) => {
            counters.unknown = counters.unknown.saturating_add(1);
        }
        ProbeOutcome::Cancelled => counters.cancelled = counters.cancelled.saturating_add(1),
        ProbeOutcome::SessionDeadline => counters.deadline = counters.deadline.saturating_add(1),
        ProbeOutcome::TransportFailed | ProbeOutcome::ContextInvalidated => {}
    }
}

fn reason_name(value: TerminalReason) -> String {
    match value {
        TerminalReason::Evidence(value) => format!("evidence:{value:?}"),
        TerminalReason::Timeout => "timeout".into(),
        TerminalReason::Cancelled => "cancelled".into(),
        TerminalReason::SessionDeadline => "deadline".into(),
        TerminalReason::TransportFailure(code) => format!("transport:{code}"),
        TerminalReason::ContextInvalidated => "contextInvalidated".into(),
    }
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nodenet_protocols::{IpAddress, Ipv4Address, ProbePort};
    use nodenetscanner_engine::{ScanTarget, TargetScope};

    #[test]
    fn result_queue_reserves_before_commit_and_saturates() {
        let mut queue = ResultQueue::new(1);
        assert_eq!(queue.try_reserve().unwrap(), SinkReservation::Reserved);
        assert_eq!(queue.try_reserve().unwrap(), SinkReservation::Saturated);
        let result = ScanResult {
            probe: LogicalProbe {
                logical_id: 0,
                attempt: 1,
                target: ScanTarget {
                    address: IpAddress::V4(Ipv4Address::new([127, 0, 0, 1])),
                    scope: None::<TargetScope>,
                },
                family: ProbeFamily::Udp,
                port: Some(ProbePort::new(7).unwrap()),
            },
            outcome: ProbeOutcome::Network(NetworkState::Open),
            evidence_strength: None,
            attempt: 1,
            transmissions: 1,
            rtt: None,
            terminal_at: MonotonicTime::from_micros(1),
            route_generation: 1,
            terminal_reason: TerminalReason::Timeout,
        };
        queue.commit_reserved(result).unwrap();
        assert_eq!(queue.take_completed_ids(), vec![0]);
        let batch = queue.take(1).unwrap();
        assert_eq!(batch.schema_version, RESULT_BATCH_SCHEMA_VERSION);
        assert_eq!(batch.row_count, 1);
        assert_eq!(batch.families, vec![4]);

        let mut queue = ResultQueue::new(4);
        for logical_id in 0..4 {
            assert_eq!(queue.try_reserve().unwrap(), SinkReservation::Reserved);
            let mut value = result;
            value.probe.logical_id = logical_id;
            queue.commit_reserved(value).unwrap();
        }
        assert_eq!(queue.try_reserve().unwrap(), SinkReservation::Saturated);
        assert_eq!(queue.application_backpressured, 1);
        assert_eq!(queue.take(1).unwrap().row_count, 1);
        assert_eq!(queue.try_reserve().unwrap(), SinkReservation::Saturated);
        assert_eq!(queue.take(1).unwrap().row_count, 1);
        assert_eq!(queue.try_reserve().unwrap(), SinkReservation::Reserved);
    }

    #[test]
    fn multicast_mac_mapping_is_protocol_correct() {
        assert_eq!(
            multicast_mac("224.0.0.1".parse().unwrap()),
            Some([1, 0, 94, 0, 0, 1])
        );
        assert_eq!(
            multicast_mac("ff02::1".parse().unwrap()),
            Some([0x33, 0x33, 0, 0, 0, 1])
        );
    }
}
