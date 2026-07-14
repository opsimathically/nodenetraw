use std::{cell::Cell, collections::BTreeSet};

use nodenet_protocols::{EvidenceStrength, IpAddress, Ipv4Address, Ipv6Address, ProbePort};
use nodenetscanner_engine::{
    Clock, ConfigError, ContextFailure, ContextResolution, ContextResolver, DiagnosticKind,
    DiscoverySilencePolicy, EmissionPurpose, EngineError, EntropySource, EvidenceEvent,
    EvidenceKind, LogicalProbe, MAX_TRANSITIONS_PER_DRIVE, MonotonicTime, NetworkState, PlanError,
    PrefixKey, ProbeDefinition, ProbeEmission, ProbeFamily, ProbeOutcome, ProbeTransport,
    ResolvedContext, ResultSink, RttEstimator, ScanDuration, ScanPlan, ScanResult, ScanScheduler,
    SchedulerConfig, SchedulingSeed, SeededPermutation, SessionLifecycle, SinkFailure,
    SinkReservation, TargetCidr, TargetEndpoint, TargetError, TargetInput, TargetIntervalInput,
    TargetScope, TargetSet, TerminalReason, TimingMode, TokenBucket, TransportFailure,
};

#[derive(Default)]
struct VirtualClock(Cell<u64>);

impl VirtualClock {
    fn set(&self, micros: u64) {
        self.0.set(micros);
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_micros(self.0.get())
    }
}

struct FixedEntropy(u64);

impl EntropySource for FixedEntropy {
    fn scheduling_seed(&mut self) -> Result<u64, EngineError> {
        Ok(self.0)
    }
}

#[derive(Default)]
struct ScriptedTransport {
    emissions: Vec<ProbeEmission>,
    fail_at: Option<usize>,
}

impl ProbeTransport for ScriptedTransport {
    fn emit(&mut self, emission: ProbeEmission) -> Result<(), TransportFailure> {
        if self.fail_at == Some(self.emissions.len()) {
            return Err(TransportFailure { code: 55 });
        }
        self.emissions.push(emission);
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ResolverMode {
    Ready { setup: Option<ProbeFamily> },
    Pending,
    Invalidated,
    Failure,
}

struct ScriptedResolver {
    mode: ResolverMode,
    generation: u64,
}

impl Default for ScriptedResolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Ready { setup: None },
            generation: 7,
        }
    }
}

impl ContextResolver for ScriptedResolver {
    fn resolve(&mut self, probe: LogicalProbe) -> Result<ContextResolution, ContextFailure> {
        if matches!(self.mode, ResolverMode::Failure) {
            return Err(ContextFailure { code: 44 });
        }
        Ok(match self.mode {
            ResolverMode::Ready { setup } => ContextResolution::Ready(ResolvedContext {
                generation: self.generation,
                prefix_key: PrefixKey::default_for(probe.target),
                neighbor_setup: setup,
            }),
            ResolverMode::Pending => ContextResolution::Pending,
            ResolverMode::Invalidated => ContextResolution::Invalidated {
                previous_generation: Some(self.generation),
            },
            ResolverMode::Failure => unreachable!("returned above"),
        })
    }
}

struct BoundedSink {
    capacity: usize,
    reserved: usize,
    results: Vec<ScanResult>,
    fail_reserve_once: bool,
    fail_commit_once: bool,
}

impl BoundedSink {
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            reserved: 0,
            results: Vec::new(),
            fail_reserve_once: false,
            fail_commit_once: false,
        }
    }
}

impl ResultSink for BoundedSink {
    fn try_reserve(&mut self) -> Result<SinkReservation, SinkFailure> {
        if self.fail_reserve_once {
            self.fail_reserve_once = false;
            return Err(SinkFailure { code: 3 });
        }
        if self.reserved + self.results.len() >= self.capacity {
            return Ok(SinkReservation::Saturated);
        }
        self.reserved += 1;
        Ok(SinkReservation::Reserved)
    }

    fn commit_reserved(&mut self, result: ScanResult) -> Result<(), SinkFailure> {
        if self.fail_commit_once {
            self.fail_commit_once = false;
            return Err(SinkFailure { code: 4 });
        }
        self.reserved = self
            .reserved
            .checked_sub(1)
            .ok_or(SinkFailure { code: 1 })?;
        self.results.push(result);
        Ok(())
    }

    fn release_reserved(&mut self, count: usize) -> Result<(), SinkFailure> {
        self.reserved = self
            .reserved
            .checked_sub(count)
            .ok_or(SinkFailure { code: 2 })?;
        Ok(())
    }
}

fn v4(octets: [u8; 4]) -> TargetEndpoint {
    TargetEndpoint::new(IpAddress::V4(Ipv4Address::new(octets)), None).expect("valid IPv4")
}

fn v6(octets: [u8; 16], scope: Option<TargetScope>) -> TargetEndpoint {
    TargetEndpoint::new(IpAddress::V6(Ipv6Address::new(octets)), scope).expect("valid IPv6")
}

fn input_address(endpoint: TargetEndpoint) -> TargetInput {
    TargetInput::Address(endpoint)
}

fn config() -> SchedulerConfig {
    SchedulerConfig {
        rate_per_second: 100_000,
        burst: 8,
        max_outstanding: 8,
        max_retransmissions: 0,
        initial_timeout: ScanDuration::from_micros(100),
        minimum_timeout: ScanDuration::from_micros(50),
        maximum_timeout: ScanDuration::from_micros(1_000),
        session_deadline: ScanDuration::from_micros(10_000),
        late_grace: ScanDuration::from_micros(500),
        max_grace_entries: 64,
        max_per_target: 8,
        max_per_prefix: 8,
        timing_mode: TimingMode::Adaptive,
        discovery_silence: DiscoverySilencePolicy::Unknown,
        tcp_reset_cleanup: false,
    }
}

fn single_plan(family: ProbeFamily) -> ScanPlan {
    let endpoint = if family.supports_ipv4() {
        v4([192, 0, 2, 10])
    } else {
        v6(
            [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10],
            None,
        )
    };
    let ports = if family.uses_ports() {
        vec![ProbePort::new(443).expect("nonzero port")]
    } else {
        Vec::new()
    };
    ScanPlan::new(
        TargetSet::normalize(&[input_address(endpoint)], &[]).expect("one target"),
        vec![ProbeDefinition::new(family, ports).expect("valid probe")],
        1,
    )
    .expect("valid plan")
}

fn arp_range_plan(count: u32) -> ScanPlan {
    let end = count
        .checked_sub(1)
        .expect("nonempty test range")
        .to_be_bytes();
    let targets = TargetSet::normalize(
        &[TargetInput::Range(TargetIntervalInput {
            start: v4([0, 0, 0, 0]),
            end: v4(end),
        })],
        &[],
    )
    .expect("compact range");
    ScanPlan::new(
        targets,
        vec![ProbeDefinition::new(ProbeFamily::Arp, Vec::new()).expect("ARP")],
        1,
    )
    .expect("plan")
}

fn large_window_config() -> SchedulerConfig {
    let mut value = config();
    value.rate_per_second = 1_000_000;
    value.burst = 5_000;
    value.max_outstanding = 5_000;
    value.max_per_target = 1;
    value.max_per_prefix = 5_000;
    value.max_grace_entries = 6_000;
    value.initial_timeout = ScanDuration::from_micros(2_000_000);
    value.minimum_timeout = ScanDuration::from_micros(2_000_000);
    value.maximum_timeout = ScanDuration::from_micros(2_000_000);
    value
}

fn scheduler(plan: ScanPlan, scheduler_config: SchedulerConfig) -> ScanScheduler {
    let permutation = SeededPermutation::new(
        plan.logical_probe_count(),
        SchedulingSeed::Explicit(0x1234_5678),
    )
    .expect("nonempty plan");
    ScanScheduler::new(plan, scheduler_config, permutation).expect("valid scheduler")
}

fn evidence(probe_id: u64, kind: EvidenceKind) -> EvidenceEvent {
    EvidenceEvent {
        probe_id,
        kind,
        strength: EvidenceStrength::StrongPayload128,
    }
}

#[test]
fn target_normalization_merges_excludes_and_decodes_compactly() {
    let includes = [
        TargetInput::Cidr(TargetCidr {
            network: v4([10, 0, 0, 3]),
            prefix_length: 29,
        }),
        TargetInput::Range(TargetIntervalInput {
            start: v4([10, 0, 0, 6]),
            end: v4([10, 0, 0, 9]),
        }),
    ];
    let excludes = [TargetInput::Range(TargetIntervalInput {
        start: v4([10, 0, 0, 2]),
        end: v4([10, 0, 0, 5]),
    })];
    let targets = TargetSet::normalize(&includes, &excludes).expect("normalizes");
    assert_eq!(targets.count(), 6);
    assert_eq!(targets.interval_count(), 2);
    let actual: Vec<_> = (0..targets.count())
        .map(|index| {
            targets
                .target_at_family(4, index)
                .expect("in range")
                .address
        })
        .collect();
    let expected =
        [0_u8, 1, 6, 7, 8, 9].map(|last| IpAddress::V4(Ipv4Address::new([10, 0, 0, last])));
    assert_eq!(actual, expected);
}

#[test]
fn target_normalization_rejects_full_width_counts_and_scope_crossings() {
    let overflow_start = 0x3000_0000_0000_0000_0000_0000_0000_0000_u128;
    let overflow_end = overflow_start + u128::from(u64::MAX);
    assert_eq!(
        TargetSet::normalize(
            &[TargetInput::Range(TargetIntervalInput {
                start: v6(overflow_start.to_be_bytes(), None),
                end: v6(overflow_end.to_be_bytes(), None),
            })],
            &[],
        ),
        Err(TargetError::TargetCountOverflow)
    );
    assert_eq!(
        TargetSet::normalize(
            &[TargetInput::Cidr(TargetCidr {
                network: TargetEndpoint {
                    address: IpAddress::V6(Ipv6Address::new([
                        0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ])),
                    scope: None,
                },
                prefix_length: 8,
            })],
            &[],
        ),
        Err(TargetError::CidrCrossesScopeBoundary)
    );
    let max = TargetEndpoint {
        address: IpAddress::V6(Ipv6Address::new([0xff; 16])),
        scope: None,
    };
    assert_eq!(
        TargetSet::normalize(&[input_address(max)], &[input_address(max)]),
        Err(TargetError::Empty)
    );
}

#[test]
fn scoped_ipv6_requires_and_preserves_a_zone() {
    let address = IpAddress::V6(Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]));
    assert_eq!(
        TargetEndpoint::new(address, None),
        Err(TargetError::MissingIpv6Scope)
    );
    let scope = TargetScope::new(3).expect("nonzero scope");
    let endpoint = TargetEndpoint::new(address, Some(scope)).expect("scoped endpoint");
    let targets = TargetSet::normalize(&[input_address(endpoint)], &[]).expect("target set");
    assert_eq!(
        targets.target_at_family(6, 0).expect("target").scope,
        Some(scope)
    );
}

#[test]
fn plan_is_a_checked_lazy_cartesian_product() {
    let targets = TargetSet::normalize(
        &[
            TargetInput::Range(TargetIntervalInput {
                start: v4([192, 0, 2, 1]),
                end: v4([192, 0, 2, 2]),
            }),
            TargetInput::Range(TargetIntervalInput {
                start: v6(
                    [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    None,
                ),
                end: v6(
                    [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                    None,
                ),
            }),
        ],
        &[],
    )
    .expect("dual-stack targets");
    let plan = ScanPlan::new(
        targets,
        vec![
            ProbeDefinition::new(ProbeFamily::Arp, Vec::new()).expect("ARP"),
            ProbeDefinition::new(ProbeFamily::Ndp, Vec::new()).expect("NDP"),
            ProbeDefinition::new(
                ProbeFamily::TcpSyn,
                vec![
                    ProbePort::new(80).expect("port"),
                    ProbePort::new(443).expect("port"),
                ],
            )
            .expect("TCP"),
        ],
        2,
    )
    .expect("plan");
    assert_eq!(plan.probes_per_attempt(), 12);
    assert_eq!(plan.logical_probe_count(), 24);
    let tuples: BTreeSet<_> = (0..plan.logical_probe_count())
        .map(|index| {
            let probe = plan.logical_probe_at(index).expect("logical probe");
            (probe.attempt, probe.target, probe.family, probe.port)
        })
        .collect();
    assert_eq!(tuples.len(), 24);
    assert_eq!(
        plan.logical_probe_at(24),
        Err(PlanError::LogicalProbeIndexOutOfRange)
    );
}

#[test]
fn plan_overflow_fails_before_tuple_materialization() {
    let start = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128;
    let end = start + u128::from(u64::MAX) - 1;
    let targets = TargetSet::normalize(
        &[TargetInput::Range(TargetIntervalInput {
            start: v6(start.to_be_bytes(), None),
            end: v6(end.to_be_bytes(), None),
        })],
        &[],
    )
    .expect("u64-sized compact target set");
    let result = ScanPlan::new(
        targets,
        vec![
            ProbeDefinition::new(
                ProbeFamily::TcpSyn,
                vec![
                    ProbePort::new(80).expect("port"),
                    ProbePort::new(81).expect("port"),
                ],
            )
            .expect("definition"),
        ],
        1,
    );
    assert_eq!(result, Err(PlanError::LogicalProbeCountOverflow));
}

#[test]
fn seeded_permutation_is_reproducible_and_bijective_at_scale() {
    for length in [1_u64, 2, 3, 16, 997, 1_000_003] {
        let first = SeededPermutation::new(length, SchedulingSeed::Explicit(99)).expect("valid");
        let second = SeededPermutation::new(length, SchedulingSeed::Explicit(99)).expect("valid");
        let mut seen = vec![false; usize::try_from(length).expect("test size")];
        for ordinal in 0..length {
            let value = first.permute(ordinal).expect("mapped ordinal");
            assert_eq!(Some(value), second.permute(ordinal));
            let index = usize::try_from(value).expect("test size");
            assert!(!seen[index]);
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|value| value));
        assert_eq!(first.permute(length), None);
    }
    let mut entropy = FixedEntropy(123);
    let hidden = SeededPermutation::from_entropy(10, &mut entropy, false).expect("entropy seed");
    assert_eq!(hidden.reported_seed(), None);
    let disclosed =
        SeededPermutation::from_entropy(10, &mut entropy, true).expect("reported entropy seed");
    assert_eq!(disclosed.reported_seed(), Some(123));
}

#[test]
fn token_bucket_and_rtt_boundaries_are_exact() {
    let mut bucket = TokenBucket::new(2, 1, MonotonicTime::from_micros(0)).expect("valid bucket");
    assert_eq!(bucket.try_take(MonotonicTime::from_micros(0)), Ok(true));
    assert_eq!(
        bucket.try_take(MonotonicTime::from_micros(499_999)),
        Ok(false)
    );
    assert_eq!(
        bucket.next_ready(MonotonicTime::from_micros(499_999)),
        Ok(MonotonicTime::from_micros(500_000))
    );
    assert_eq!(
        bucket.try_take(MonotonicTime::from_micros(500_000)),
        Ok(true)
    );

    let mut stress =
        TokenBucket::new(1_000_000, 1, MonotonicTime::from_micros(0)).expect("valid stress bucket");
    for now in 0..1_000_000_u64 {
        assert_eq!(stress.try_take(MonotonicTime::from_micros(now)), Ok(true));
    }

    let mut estimator = RttEstimator::default();
    estimator.observe(ScanDuration::from_micros(100));
    assert_eq!(estimator.samples(), 1);
    assert_eq!(
        estimator.timeout(
            TimingMode::Adaptive,
            ScanDuration::from_micros(1_000),
            ScanDuration::from_micros(50),
            ScanDuration::from_micros(1_000),
        ),
        Ok(ScanDuration::from_micros(300))
    );
    assert_eq!(
        TokenBucket::new(0, 1, MonotonicTime::from_micros(0)),
        Err(ConfigError::InvalidRate)
    );
}

#[test]
fn configuration_reports_fixed_timing_tradeoff_and_rejects_limits() {
    let mut value = config();
    value.timing_mode = TimingMode::FixedRate;
    assert!(
        value
            .validate()
            .expect("valid")
            .accuracy_tradeoff_reported()
    );
    value.rate_per_second = 0;
    assert_eq!(value.validate(), Err(ConfigError::InvalidRate));
}

#[test]
fn all_supported_evidence_classifications_are_explicit() {
    let cases = [
        (
            ProbeFamily::TcpSyn,
            EvidenceKind::TcpSynAcknowledgment,
            NetworkState::Open,
        ),
        (
            ProbeFamily::TcpSyn,
            EvidenceKind::TcpReset,
            NetworkState::Closed,
        ),
        (
            ProbeFamily::TcpSyn,
            EvidenceKind::IcmpOtherError,
            NetworkState::Filtered,
        ),
        (ProbeFamily::Udp, EvidenceKind::UdpReply, NetworkState::Open),
        (
            ProbeFamily::Udp,
            EvidenceKind::IcmpPortUnreachable,
            NetworkState::Closed,
        ),
        (
            ProbeFamily::Udp,
            EvidenceKind::ExplicitUnreachable,
            NetworkState::Filtered,
        ),
        (ProbeFamily::Arp, EvidenceKind::ArpReply, NetworkState::Up),
        (
            ProbeFamily::Arp,
            EvidenceKind::ExplicitUnreachable,
            NetworkState::Unreachable,
        ),
        (
            ProbeFamily::Ndp,
            EvidenceKind::NeighborAdvertisement,
            NetworkState::Up,
        ),
        (
            ProbeFamily::Icmpv4Echo,
            EvidenceKind::EchoReply,
            NetworkState::Up,
        ),
        (
            ProbeFamily::Icmpv6Echo,
            EvidenceKind::IcmpOtherError,
            NetworkState::Unreachable,
        ),
    ];
    for (family, kind, expected) in cases {
        let plan = single_plan(family);
        let mut engine = scheduler(plan, config());
        let clock = VirtualClock::default();
        let mut transport = ScriptedTransport::default();
        let mut resolver = ScriptedResolver::default();
        let mut sink = BoundedSink::new(8);
        engine.start(&clock).expect("start");
        engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("drive");
        let probe_id = transport.emissions[0].probe_id;
        clock.set(10);
        engine
            .handle_evidence(&clock, evidence(probe_id, kind), &mut transport, &mut sink)
            .expect("evidence");
        assert_eq!(sink.results.len(), 1, "{family:?} {kind:?}");
        assert_eq!(sink.results[0].outcome, ProbeOutcome::Network(expected));
        assert_eq!(sink.results[0].route_generation, 7);
        assert_eq!(sink.results[0].rtt, Some(ScanDuration::from_micros(10)));
        assert_eq!(
            sink.results[0].terminal_reason,
            TerminalReason::Evidence(kind)
        );
    }
}

#[test]
fn silence_retry_backoff_and_exact_deadline_are_deterministic() {
    let mut scheduler_config = config();
    scheduler_config.max_retransmissions = 2;
    let mut engine = scheduler(single_plan(ProbeFamily::TcpSyn), scheduler_config);
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("first");
    for boundary in [100_u64, 300, 700] {
        clock.set(boundary);
        engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("boundary");
    }
    assert_eq!(transport.emissions.len(), 3);
    assert_eq!(sink.results.len(), 1);
    assert_eq!(
        sink.results[0].outcome,
        ProbeOutcome::Network(NetworkState::Filtered)
    );
    assert_eq!(sink.results[0].transmissions, 3);
    assert_eq!(sink.results[0].terminal_reason, TerminalReason::Timeout);
}

#[test]
fn discovery_and_udp_silence_never_claim_more_than_policy_allows() {
    for (family, expected) in [
        (ProbeFamily::Udp, NetworkState::OpenOrFiltered),
        (ProbeFamily::Arp, NetworkState::Unknown),
    ] {
        let mut engine = scheduler(single_plan(family), config());
        let clock = VirtualClock::default();
        let mut transport = ScriptedTransport::default();
        let mut resolver = ScriptedResolver::default();
        let mut sink = BoundedSink::new(8);
        engine.start(&clock).expect("start");
        engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("emit");
        clock.set(100);
        engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("timeout");
        assert_eq!(sink.results[0].outcome, ProbeOutcome::Network(expected));
    }
}

#[test]
fn pause_queues_but_does_not_transmit_a_due_retry() {
    let mut scheduler_config = config();
    scheduler_config.max_retransmissions = 1;
    let mut engine = scheduler(single_plan(ProbeFamily::TcpSyn), scheduler_config);
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("emit");
    engine.request_pause().expect("pause request");
    clock.set(100);
    let paused = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("pause");
    assert_eq!(paused.lifecycle, SessionLifecycle::Paused);
    assert_eq!(transport.emissions.len(), 1);
    assert!(sink.results.is_empty());
    engine.resume().expect("resume");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("retry");
    assert_eq!(transport.emissions.len(), 2);
}

#[test]
fn neighbor_setup_and_tcp_cleanup_are_rate_charged_transmissions() {
    let mut engine = scheduler(single_plan(ProbeFamily::Icmpv4Echo), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver {
        mode: ResolverMode::Ready {
            setup: Some(ProbeFamily::Arp),
        },
        generation: 9,
    };
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("ARP");
    assert!(matches!(
        transport.emissions[0].purpose,
        EmissionPurpose::NeighborSetup(ProbeFamily::Arp)
    ));
    clock.set(5);
    let id = transport.emissions[0].probe_id;
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::IcmpOtherError),
            &mut transport,
            &mut sink,
        )
        .expect("probe evidence cannot classify neighbor setup");
    assert!(sink.results.is_empty());
    assert_eq!(engine.diagnostics().forged_or_unrelated, 1);
    clock.set(10);
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::NeighborResolved),
            &mut transport,
            &mut sink,
        )
        .expect("neighbor evidence");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("probe");
    clock.set(20);
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::EchoReply),
            &mut transport,
            &mut sink,
        )
        .expect("echo");
    assert_eq!(transport.emissions.len(), 2);
    assert_eq!(sink.results[0].transmissions, 2);

    let mut cleanup_config = config();
    cleanup_config.tcp_reset_cleanup = true;
    let mut cleanup = scheduler(single_plan(ProbeFamily::TcpSyn), cleanup_config);
    let cleanup_clock = VirtualClock::default();
    let mut cleanup_transport = ScriptedTransport::default();
    let mut cleanup_resolver = ScriptedResolver::default();
    let mut cleanup_sink = BoundedSink::new(8);
    cleanup.start(&cleanup_clock).expect("start");
    cleanup
        .drive(
            &cleanup_clock,
            &mut cleanup_transport,
            &mut cleanup_resolver,
            &mut cleanup_sink,
        )
        .expect("SYN");
    cleanup_clock.set(10);
    let cleanup_id = cleanup_transport.emissions[0].probe_id;
    cleanup
        .handle_evidence(
            &cleanup_clock,
            evidence(cleanup_id, EvidenceKind::TcpSynAcknowledgment),
            &mut cleanup_transport,
            &mut cleanup_sink,
        )
        .expect("SYN-ACK");
    assert_eq!(cleanup_transport.emissions.len(), 2);
    assert_eq!(
        cleanup_transport.emissions[1].purpose,
        EmissionPurpose::TcpResetCleanup
    );
    assert_eq!(cleanup_sink.results[0].transmissions, 2);
}

#[test]
fn duplicates_forgery_invalid_evidence_and_parser_diagnostics_never_guess_results() {
    let mut engine = scheduler(single_plan(ProbeFamily::Udp), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("emit");
    let id = transport.emissions[0].probe_id;
    clock.set(10);
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::TcpSynAcknowledgment),
            &mut transport,
            &mut sink,
        )
        .expect("invalid evidence is diagnostic");
    assert!(sink.results.is_empty());
    engine
        .handle_evidence(
            &clock,
            evidence(id + 99, EvidenceKind::UdpReply),
            &mut transport,
            &mut sink,
        )
        .expect("unrelated evidence");
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::UdpReply),
            &mut transport,
            &mut sink,
        )
        .expect("valid evidence");
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::UdpReply),
            &mut transport,
            &mut sink,
        )
        .expect("duplicate evidence");
    engine.record_diagnostic(DiagnosticKind::NonFirstFragment);
    engine.record_diagnostic(DiagnosticKind::OpaqueProtocol);
    engine.record_diagnostic(DiagnosticKind::InsufficientQuote);
    let diagnostics = engine.diagnostics();
    assert_eq!(sink.results.len(), 1);
    assert_eq!(diagnostics.forged_or_unrelated, 2);
    assert_eq!(diagnostics.duplicates, 1);
    assert_eq!(diagnostics.late_responses, 1);
    assert_eq!(diagnostics.non_first_fragment, 1);
    assert_eq!(diagnostics.opaque_protocol, 1);
    assert_eq!(diagnostics.insufficient_quote, 1);
}

#[test]
fn exact_timeout_boundary_wins_and_late_evidence_cannot_resurrect() {
    let mut engine = scheduler(single_plan(ProbeFamily::TcpSyn), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("emit");
    let id = transport.emissions[0].probe_id;
    clock.set(100);
    engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::TcpSynAcknowledgment),
            &mut transport,
            &mut sink,
        )
        .expect("boundary");
    assert_eq!(sink.results.len(), 1);
    assert_eq!(sink.results[0].terminal_reason, TerminalReason::Timeout);
    assert_eq!(engine.diagnostics().late_responses, 1);
}

#[test]
fn backpressure_and_context_states_stop_admission_without_emission() {
    for mode in [
        ResolverMode::Ready { setup: None },
        ResolverMode::Pending,
        ResolverMode::Invalidated,
    ] {
        let mut engine = scheduler(single_plan(ProbeFamily::Arp), config());
        let clock = VirtualClock::default();
        let mut transport = ScriptedTransport::default();
        let mut resolver = ScriptedResolver {
            mode,
            generation: 3,
        };
        let mut sink = BoundedSink::new(if matches!(mode, ResolverMode::Ready { .. }) {
            0
        } else {
            8
        });
        engine.start(&clock).expect("start");
        let report = engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("drive");
        assert!(transport.emissions.is_empty());
        assert_eq!(report.outstanding, 0);
        if matches!(mode, ResolverMode::Ready { .. }) {
            assert!(report.sink_backpressured);
        } else {
            assert!(report.context_waiting);
        }
    }
}

#[test]
fn pending_context_requires_an_explicit_restoration_boundary() {
    let mut engine = scheduler(single_plan(ProbeFamily::Arp), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver {
        mode: ResolverMode::Pending,
        generation: 1,
    };
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    let waiting = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("pending context");
    assert!(waiting.context_waiting);
    resolver.mode = ResolverMode::Ready { setup: None };
    let still_waiting = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("restoration not yet signalled");
    assert!(still_waiting.context_waiting);
    assert!(transport.emissions.is_empty());
    engine.context_restored();
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("restored context");
    assert_eq!(transport.emissions.len(), 1);
}

#[test]
fn target_and_prefix_fairness_bound_quiet_targets() {
    let targets = TargetSet::normalize(
        &[TargetInput::Range(TargetIntervalInput {
            start: v4([198, 51, 100, 1]),
            end: v4([198, 51, 100, 4]),
        })],
        &[],
    )
    .expect("targets");
    let plan = ScanPlan::new(
        targets,
        vec![
            ProbeDefinition::new(
                ProbeFamily::TcpSyn,
                vec![
                    ProbePort::new(80).expect("port"),
                    ProbePort::new(443).expect("port"),
                ],
            )
            .expect("TCP"),
        ],
        1,
    )
    .expect("plan");
    let mut scheduler_config = config();
    scheduler_config.max_per_target = 1;
    scheduler_config.max_per_prefix = 2;
    let mut engine = scheduler(plan, scheduler_config);
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(16);
    engine.start(&clock).expect("start");
    let report = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("drive");
    assert_eq!(report.outstanding, 2);
    let targets: BTreeSet<_> = transport
        .emissions
        .iter()
        .map(|value| value.probe.target)
        .collect();
    assert_eq!(targets.len(), 2);
}

#[test]
fn prefixes_protocols_sessions_and_reordered_replies_all_progress() {
    let targets = TargetSet::normalize(
        &[
            input_address(v4([198, 51, 100, 1])),
            input_address(v4([203, 0, 113, 1])),
        ],
        &[],
    )
    .expect("two prefixes");
    let plan = ScanPlan::new(
        targets,
        vec![
            ProbeDefinition::new(
                ProbeFamily::TcpSyn,
                vec![ProbePort::new(443).expect("port")],
            )
            .expect("TCP"),
        ],
        1,
    )
    .expect("plan");
    let mut scheduler_config = config();
    scheduler_config.max_per_prefix = 1;
    let mut first = scheduler(plan, scheduler_config);
    let clock = VirtualClock::default();
    let mut first_transport = ScriptedTransport::default();
    let mut first_resolver = ScriptedResolver::default();
    let mut first_sink = BoundedSink::new(8);
    first.start(&clock).expect("start first session");
    first
        .drive(
            &clock,
            &mut first_transport,
            &mut first_resolver,
            &mut first_sink,
        )
        .expect("drive first session");
    let prefixes: BTreeSet<_> = first_transport
        .emissions
        .iter()
        .map(|value| PrefixKey::default_for(value.probe.target))
        .collect();
    assert_eq!(prefixes.len(), 2);

    for emission in first_transport.emissions.clone().into_iter().rev() {
        clock.set(clock.now().as_micros() + 1);
        first
            .handle_evidence(
                &clock,
                evidence(emission.probe_id, EvidenceKind::TcpReset),
                &mut first_transport,
                &mut first_sink,
            )
            .expect("reordered response");
    }
    assert_eq!(first_sink.results.len(), 2);

    let mixed_targets =
        TargetSet::normalize(&[input_address(v4([192, 0, 2, 1]))], &[]).expect("mixed target");
    let mixed_plan = ScanPlan::new(
        mixed_targets,
        vec![
            ProbeDefinition::new(ProbeFamily::Arp, Vec::new()).expect("ARP"),
            ProbeDefinition::new(ProbeFamily::Udp, vec![ProbePort::new(53).expect("port")])
                .expect("UDP"),
        ],
        1,
    )
    .expect("mixed plan");
    let mut second = scheduler(mixed_plan, config());
    let mut second_transport = ScriptedTransport::default();
    let mut second_resolver = ScriptedResolver::default();
    let mut second_sink = BoundedSink::new(8);
    second.start(&clock).expect("start second session");
    second
        .drive(
            &clock,
            &mut second_transport,
            &mut second_resolver,
            &mut second_sink,
        )
        .expect("round-robin second session");
    let protocols: BTreeSet<_> = second_transport
        .emissions
        .iter()
        .map(|value| value.probe.family)
        .collect();
    assert_eq!(
        protocols,
        BTreeSet::from([ProbeFamily::Arp, ProbeFamily::Udp])
    );
    assert_eq!(first.lifecycle(), SessionLifecycle::Completed);
    assert_eq!(second.lifecycle(), SessionLifecycle::Running);
}

#[test]
fn cancellation_deadline_context_and_transport_have_terminal_results() {
    let mut cancelled = scheduler(single_plan(ProbeFamily::Arp), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    cancelled.start(&clock).expect("start");
    cancelled
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("emit");
    cancelled.cancel(&clock, &mut sink).expect("cancel");
    assert_eq!(cancelled.lifecycle(), SessionLifecycle::Completed);
    assert_eq!(sink.results[0].outcome, ProbeOutcome::Cancelled);

    let mut invalidated = scheduler(single_plan(ProbeFamily::Arp), config());
    let mut invalidated_transport = ScriptedTransport::default();
    let mut invalidated_resolver = ScriptedResolver::default();
    let mut invalidated_sink = BoundedSink::new(8);
    invalidated.start(&clock).expect("start");
    invalidated
        .drive(
            &clock,
            &mut invalidated_transport,
            &mut invalidated_resolver,
            &mut invalidated_sink,
        )
        .expect("emit");
    invalidated
        .invalidate_context(&clock, Some(7), &mut invalidated_sink)
        .expect("invalidate");
    assert_eq!(
        invalidated_sink.results[0].outcome,
        ProbeOutcome::ContextInvalidated
    );

    let mut failed = scheduler(single_plan(ProbeFamily::Arp), config());
    let mut failed_transport = ScriptedTransport {
        emissions: Vec::new(),
        fail_at: Some(0),
    };
    let mut failed_resolver = ScriptedResolver::default();
    let mut failed_sink = BoundedSink::new(8);
    failed.start(&clock).expect("start");
    let report = failed
        .drive(
            &clock,
            &mut failed_transport,
            &mut failed_resolver,
            &mut failed_sink,
        )
        .expect("transport failure becomes terminal state");
    assert_eq!(report.lifecycle, SessionLifecycle::Failed);
    assert_eq!(
        failed_sink.results[0].outcome,
        ProbeOutcome::TransportFailed
    );
    assert_eq!(
        failed_sink.results[0].terminal_reason,
        TerminalReason::TransportFailure(55)
    );
    assert_eq!(failed_sink.results[0].transmissions, 1);
}

#[test]
fn external_context_and_receive_failures_have_terminal_results() {
    let clock = VirtualClock::default();
    let mut receive_failed = scheduler(single_plan(ProbeFamily::Arp), config());
    let mut receive_transport = ScriptedTransport::default();
    let mut receive_resolver = ScriptedResolver::default();
    let mut receive_sink = BoundedSink::new(8);
    receive_failed.start(&clock).expect("start");
    receive_failed
        .drive(
            &clock,
            &mut receive_transport,
            &mut receive_resolver,
            &mut receive_sink,
        )
        .expect("emit");
    receive_failed
        .transport_failed(&clock, 77, &mut receive_sink)
        .expect("fail receive transport");
    assert_eq!(receive_failed.lifecycle(), SessionLifecycle::Failed);
    assert_eq!(
        receive_sink.results[0].outcome,
        ProbeOutcome::TransportFailed
    );
    assert_eq!(
        receive_sink.results[0].terminal_reason,
        TerminalReason::TransportFailure(77)
    );

    let mut context_failed = scheduler(single_plan(ProbeFamily::Arp), config());
    let mut context_transport = ScriptedTransport::default();
    let mut context_resolver = ScriptedResolver::default();
    let mut context_sink = BoundedSink::new(8);
    context_failed.start(&clock).expect("start");
    context_failed
        .drive(
            &clock,
            &mut context_transport,
            &mut context_resolver,
            &mut context_sink,
        )
        .expect("emit");
    context_failed
        .context_failed(&clock, &mut context_sink)
        .expect("fail context");
    assert_eq!(context_failed.lifecycle(), SessionLifecycle::Failed);
    assert_eq!(
        context_sink.results[0].outcome,
        ProbeOutcome::ContextInvalidated
    );
}

#[test]
fn deadline_draining_obeys_the_per_drive_transition_budget() {
    let plan = arp_range_plan(5_000);
    let mut scheduler_config = large_window_config();
    scheduler_config.session_deadline = ScanDuration::from_micros(1_000_000);
    let mut engine = scheduler(plan, scheduler_config);
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(6_000);
    engine.start(&clock).expect("start");
    while transport.emissions.len() < 5_000 {
        let report = engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("fill");
        assert!(report.transitions <= MAX_TRANSITIONS_PER_DRIVE);
    }
    clock.set(1_000_000);
    let first = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("deadline");
    assert_eq!(first.transitions, MAX_TRANSITIONS_PER_DRIVE);
    assert_eq!(first.lifecycle, SessionLifecycle::Cancelling);
    let second = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("drain");
    assert!(second.transitions <= MAX_TRANSITIONS_PER_DRIVE);
    assert_eq!(second.lifecycle, SessionLifecycle::Completed);
    assert_eq!(sink.results.len(), 5_000);
    assert!(
        sink.results
            .iter()
            .all(|value| value.outcome == ProbeOutcome::SessionDeadline)
    );
}

#[test]
fn context_invalidation_draining_obeys_the_per_drive_transition_budget() {
    let mut engine = scheduler(arp_range_plan(5_000), large_window_config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(6_000);
    engine.start(&clock).expect("start");
    while transport.emissions.len() < 5_000 {
        engine
            .drive(&clock, &mut transport, &mut resolver, &mut sink)
            .expect("fill");
    }
    engine
        .invalidate_context(&clock, Some(7), &mut sink)
        .expect("begin bounded invalidation");
    assert_eq!(sink.results.len(), MAX_TRANSITIONS_PER_DRIVE);
    assert_eq!(engine.lifecycle(), SessionLifecycle::Running);
    let remainder = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("drain invalidation");
    assert_eq!(remainder.transitions, 5_000 - MAX_TRANSITIONS_PER_DRIVE);
    assert_eq!(remainder.lifecycle, SessionLifecycle::Completed);
    assert_eq!(sink.results.len(), 5_000);
    assert!(
        sink.results
            .iter()
            .all(|value| value.outcome == ProbeOutcome::ContextInvalidated)
    );
}

#[test]
fn huge_logical_plan_keeps_state_proportional_to_the_active_window() {
    let targets = TargetSet::normalize(
        &[TargetInput::Cidr(TargetCidr {
            network: v4([10, 0, 0, 0]),
            prefix_length: 8,
        })],
        &[],
    )
    .expect("large compact target set");
    let plan = ScanPlan::new(
        targets,
        vec![ProbeDefinition::new(ProbeFamily::Arp, Vec::new()).expect("ARP")],
        1,
    )
    .expect("large lazy plan");
    assert_eq!(plan.logical_probe_count(), 16_777_216);
    let mut scheduler_config = config();
    scheduler_config.burst = 2;
    scheduler_config.max_outstanding = 2;
    scheduler_config.max_per_target = 1;
    scheduler_config.max_per_prefix = 2;
    let mut engine = scheduler(plan, scheduler_config);
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    let report = engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("drive");
    assert_eq!(report.outstanding, 2);
    assert_eq!(report.deferred, 0);
}

fn replay(seed: u64) -> (Vec<ProbeEmission>, Vec<ScanResult>) {
    let targets = TargetSet::normalize(
        &[TargetInput::Range(TargetIntervalInput {
            start: v4([203, 0, 113, 1]),
            end: v4([203, 0, 113, 3]),
        })],
        &[],
    )
    .expect("targets");
    let plan = ScanPlan::new(
        targets,
        vec![ProbeDefinition::new(ProbeFamily::Icmpv4Echo, Vec::new()).expect("echo")],
        1,
    )
    .expect("plan");
    let permutation =
        SeededPermutation::new(plan.logical_probe_count(), SchedulingSeed::Explicit(seed))
            .expect("permutation");
    let mut engine = ScanScheduler::new(plan, config(), permutation).expect("scheduler");
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver::default();
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("emit");
    let emissions = transport.emissions.clone();
    for (offset, emission) in emissions.iter().enumerate() {
        clock.set(u64::try_from(offset + 1).expect("small replay"));
        engine
            .handle_evidence(
                &clock,
                evidence(emission.probe_id, EvidenceKind::EchoReply),
                &mut transport,
                &mut sink,
            )
            .expect("evidence");
    }
    (transport.emissions, sink.results)
}

#[test]
fn recorded_stream_replay_is_byte_for_byte_deterministic() {
    assert_eq!(replay(0xfeed_beef), replay(0xfeed_beef));
}

#[test]
fn collaborator_failures_preserve_unadmitted_and_reserved_work() {
    let mut context_engine = scheduler(single_plan(ProbeFamily::Arp), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver {
        mode: ResolverMode::Failure,
        generation: 1,
    };
    let mut sink = BoundedSink::new(8);
    context_engine.start(&clock).expect("start");
    assert_eq!(
        context_engine.drive(&clock, &mut transport, &mut resolver, &mut sink),
        Err(EngineError::Context(ContextFailure { code: 44 }))
    );
    resolver.mode = ResolverMode::Ready { setup: None };
    context_engine
        .drive(&clock, &mut transport, &mut resolver, &mut sink)
        .expect("context retry");
    assert_eq!(transport.emissions.len(), 1);

    let mut reserve_engine = scheduler(single_plan(ProbeFamily::Arp), config());
    let mut reserve_transport = ScriptedTransport::default();
    let mut reserve_resolver = ScriptedResolver::default();
    let mut reserve_sink = BoundedSink::new(8);
    reserve_sink.fail_reserve_once = true;
    reserve_engine.start(&clock).expect("start");
    assert_eq!(
        reserve_engine.drive(
            &clock,
            &mut reserve_transport,
            &mut reserve_resolver,
            &mut reserve_sink,
        ),
        Err(EngineError::Sink(SinkFailure { code: 3 }))
    );
    reserve_engine
        .drive(
            &clock,
            &mut reserve_transport,
            &mut reserve_resolver,
            &mut reserve_sink,
        )
        .expect("reservation retry");
    assert_eq!(reserve_transport.emissions.len(), 1);

    reserve_sink.fail_commit_once = true;
    let id = reserve_transport.emissions[0].probe_id;
    clock.set(10);
    assert_eq!(
        reserve_engine.handle_evidence(
            &clock,
            evidence(id, EvidenceKind::ArpReply),
            &mut reserve_transport,
            &mut reserve_sink,
        ),
        Err(EngineError::Sink(SinkFailure { code: 4 }))
    );
    assert_eq!(reserve_sink.reserved, 1);
    assert!(reserve_sink.results.is_empty());
    reserve_engine
        .handle_evidence(
            &clock,
            evidence(id, EvidenceKind::ArpReply),
            &mut reserve_transport,
            &mut reserve_sink,
        )
        .expect("commit retry");
    assert_eq!(reserve_sink.results.len(), 1);
}

#[test]
fn invalid_neighbor_setup_is_rejected_before_emission() {
    let mut engine = scheduler(single_plan(ProbeFamily::Icmpv4Echo), config());
    let clock = VirtualClock::default();
    let mut transport = ScriptedTransport::default();
    let mut resolver = ScriptedResolver {
        mode: ResolverMode::Ready {
            setup: Some(ProbeFamily::Ndp),
        },
        generation: 1,
    };
    let mut sink = BoundedSink::new(8);
    engine.start(&clock).expect("start");
    assert_eq!(
        engine.drive(&clock, &mut transport, &mut resolver, &mut sink),
        Err(EngineError::InvalidContext)
    );
    assert!(transport.emissions.is_empty());
}
