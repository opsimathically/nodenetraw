use core::fmt;
use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    IpAddress, IpProtocol, MAX_CORRELATION_LEASES, ParsedTcpSegment, Port, QuotedIpPacket,
    QuotedTransport, TcpFlags,
};

const CORRELATION_DOMAIN: &[u8; 16] = b"nodenet/probe/v1";
const CANONICAL_INPUT_LENGTH: usize = 70;

/// A distinct 32-byte session secret obtained by the caller from OS entropy.
///
/// This syscall-free crate intentionally cannot create entropy. The future
/// scanner runtime owns random generation and passes one independent key here.
pub struct SessionSecret([u8; 32]);

impl SessionSecret {
    /// Wraps 32 bytes supplied by the native runtime's OS random source.
    #[must_use]
    pub const fn from_os_random(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives the fixed-width token for one exact probe identity.
    #[must_use]
    pub fn derive(&self, identity: ProbeIdentity) -> CorrelationToken {
        let input = identity.canonical_input();
        let mut block_key = [0_u8; 64];
        block_key[..32].copy_from_slice(&self.0);
        let mut mac = <Hmac<Sha256> as KeyInit>::new(&block_key.into());
        block_key.zeroize();
        mac.update(&input);
        let output = mac.finalize().into_bytes();
        let mut token = [0_u8; 32];
        token.copy_from_slice(&output);
        CorrelationToken(token)
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionSecret([REDACTED])")
    }
}

impl Drop for SessionSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Every field cryptographically bound to a probe correlation token.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProbeIdentity {
    protocol: IpProtocol,
    attempt: u32,
    source: IpAddress,
    destination: IpAddress,
    source_port: Port,
    destination_port: Port,
    icmp_identifier: u16,
    icmp_sequence: u16,
    probe_id: u64,
}

impl ProbeIdentity {
    /// Creates one correlation identity after enforcing one address family.
    ///
    /// # Errors
    ///
    /// Rejects mixed IPv4/IPv6 source and destination addresses.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor mirrors every field in the frozen correlation encoding"
    )]
    pub const fn new(
        protocol: IpProtocol,
        attempt: u32,
        source: IpAddress,
        destination: IpAddress,
        source_port: Port,
        destination_port: Port,
        icmp_identifier: u16,
        icmp_sequence: u16,
        probe_id: u64,
    ) -> Result<Self, CorrelationIdentityError> {
        if !matches!(
            (source, destination),
            (IpAddress::V4(_), IpAddress::V4(_)) | (IpAddress::V6(_), IpAddress::V6(_))
        ) {
            return Err(CorrelationIdentityError::AddressFamilyMismatch);
        }
        Ok(Self {
            protocol,
            attempt,
            source,
            destination,
            source_port,
            destination_port,
            icmp_identifier,
            icmp_sequence,
            probe_id,
        })
    }

    #[must_use]
    pub const fn protocol(self) -> IpProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn source(self) -> IpAddress {
        self.source
    }

    #[must_use]
    pub const fn destination(self) -> IpAddress {
        self.destination
    }

    fn canonical_input(self) -> [u8; CANONICAL_INPUT_LENGTH] {
        let mut input = [0_u8; CANONICAL_INPUT_LENGTH];
        input[..16].copy_from_slice(CORRELATION_DOMAIN);
        let (family, source, destination) = canonical_addresses(self.source, self.destination);
        input[16] = family;
        input[17] = self.protocol.get();
        input[18..22].copy_from_slice(&self.attempt.to_be_bytes());
        input[22..38].copy_from_slice(&source);
        input[38..54].copy_from_slice(&destination);
        input[54..56].copy_from_slice(&self.source_port.get().to_be_bytes());
        input[56..58].copy_from_slice(&self.destination_port.get().to_be_bytes());
        input[58..60].copy_from_slice(&self.icmp_identifier.to_be_bytes());
        input[60..62].copy_from_slice(&self.icmp_sequence.to_be_bytes());
        input[62..70].copy_from_slice(&self.probe_id.to_be_bytes());
        input
    }
}

/// Probe identity construction errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CorrelationIdentityError {
    AddressFamilyMismatch,
}

impl fmt::Display for CorrelationIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("probe correlation addresses use different IP families")
    }
}

impl std::error::Error for CorrelationIdentityError {}

/// The complete HMAC-SHA-256 correlation output.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CorrelationToken([u8; 32]);

impl CorrelationToken {
    #[must_use]
    pub const fn full(self) -> [u8; 32] {
        self.0
    }

    /// The 128-bit token carried by UDP and ICMP probe payloads.
    #[must_use]
    pub fn payload_token(self) -> [u8; 16] {
        let mut output = [0_u8; 16];
        output.copy_from_slice(&self.0[..16]);
        output
    }

    /// The 32-bit token carried in the TCP sequence field.
    #[must_use]
    pub const fn tcp_sequence(self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// The exact acknowledgment expected from a tokenized TCP probe.
    #[must_use]
    pub const fn tcp_acknowledgment(self) -> u32 {
        self.tcp_sequence().wrapping_add(1)
    }

    fn payload_matches(self, candidate: &[u8]) -> bool {
        candidate.len() == 16 && bool::from(self.0[..16].ct_eq(candidate))
    }
}

impl fmt::Debug for CorrelationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CorrelationToken")
            .field(&self.0)
            .finish()
    }
}

/// A direct response tuple in receive direction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResponseTuple {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub source_port: Port,
    pub destination_port: Port,
}

/// The amount and kind of forgery resistance established by classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EvidenceStrength {
    /// Tuple, interface, and receive-window correlation without a secret token.
    TupleCorrelatedUnauthenticated,
    /// A valid quote lacked enough payload bytes to authenticate its token.
    TruncatedQuote,
    /// The exact 32-bit HMAC-derived TCP sequence was acknowledged or quoted.
    StrongTcpSequence32,
    /// The exact 128-bit HMAC-derived payload token was returned or quoted.
    StrongPayload128,
}

/// Protocol meaning of a successfully correlated response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CorrelationEvidenceKind {
    TcpSynAcknowledgment,
    TcpReset,
    EchoReply,
    UdpReply,
    IcmpErrorQuote,
    ArpReply,
    NeighborAdvertisement,
}

/// A normalized, policy-free response observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CorrelationEvidence {
    pub kind: CorrelationEvidenceKind,
    pub strength: EvidenceStrength,
}

/// A failed response-correlation check.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CorrelationRejection {
    TupleMismatch,
    ProtocolMismatch,
    InvalidFlags,
    TokenMismatch,
    FragmentedQuote,
    InsufficientQuote,
}

/// Classifies a checksum-validated TCP reply without applying scan policy.
///
/// # Errors
///
/// Rejects protocol, tuple, flag, or acknowledgment-token mismatches.
pub fn classify_tcp_reply(
    expected: ProbeIdentity,
    token: CorrelationToken,
    tuple: ResponseTuple,
    segment: ParsedTcpSegment<'_>,
) -> Result<CorrelationEvidence, CorrelationRejection> {
    if expected.protocol.get() != 6 {
        return Err(CorrelationRejection::ProtocolMismatch);
    }
    if !reverse_tuple_matches(expected, tuple)
        || tuple.source_port != segment.source_port
        || tuple.destination_port != segment.destination_port
    {
        return Err(CorrelationRejection::TupleMismatch);
    }
    let acknowledgment = segment.flags.contains(TcpFlags::ACK);
    let synchronization = segment.flags.contains(TcpFlags::SYN);
    let reset = segment.flags.contains(TcpFlags::RST);
    if !acknowledgment || synchronization == reset {
        return Err(CorrelationRejection::InvalidFlags);
    }
    if segment.acknowledgment_number != token.tcp_acknowledgment() {
        return Err(CorrelationRejection::TokenMismatch);
    }
    Ok(CorrelationEvidence {
        kind: if reset {
            CorrelationEvidenceKind::TcpReset
        } else {
            CorrelationEvidenceKind::TcpSynAcknowledgment
        },
        strength: EvidenceStrength::StrongTcpSequence32,
    })
}

/// Classifies a direct ICMP Echo reply using exact tuple and 128-bit token checks.
///
/// # Errors
///
/// Rejects protocol, tuple, identifier, sequence, or payload-token mismatches.
pub fn classify_echo_reply(
    expected: ProbeIdentity,
    source: IpAddress,
    destination: IpAddress,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    token: CorrelationToken,
) -> Result<CorrelationEvidence, CorrelationRejection> {
    if !matches!(expected.protocol.get(), 1 | 58) {
        return Err(CorrelationRejection::ProtocolMismatch);
    }
    if source != expected.destination
        || destination != expected.source
        || identifier != expected.icmp_identifier
        || sequence != expected.icmp_sequence
    {
        return Err(CorrelationRejection::TupleMismatch);
    }
    if payload.len() < 16 || !token.payload_matches(&payload[..16]) {
        return Err(CorrelationRejection::TokenMismatch);
    }
    Ok(CorrelationEvidence {
        kind: CorrelationEvidenceKind::EchoReply,
        strength: EvidenceStrength::StrongPayload128,
    })
}

/// Classifies a direct UDP reply. UDP applications need not echo probe bytes,
/// so the result is intentionally unauthenticated even if payloads coincide.
///
/// # Errors
///
/// Rejects protocol or reverse-tuple mismatches.
pub fn classify_udp_reply(
    expected: ProbeIdentity,
    tuple: ResponseTuple,
) -> Result<CorrelationEvidence, CorrelationRejection> {
    if expected.protocol.get() != 17 {
        return Err(CorrelationRejection::ProtocolMismatch);
    }
    if !reverse_tuple_matches(expected, tuple) {
        return Err(CorrelationRejection::TupleMismatch);
    }
    Ok(CorrelationEvidence {
        kind: CorrelationEvidenceKind::UdpReply,
        strength: EvidenceStrength::TupleCorrelatedUnauthenticated,
    })
}

/// Classifies an ICMP-quoted original probe, preserving explicit weak evidence
/// when an otherwise valid quote ends before the token.
///
/// # Errors
///
/// Rejects tuple/protocol/token mismatches and unusable fragment or short quotes.
pub fn classify_quoted_response(
    expected: ProbeIdentity,
    quote: QuotedIpPacket<'_>,
    token: CorrelationToken,
) -> Result<CorrelationEvidence, CorrelationRejection> {
    if quote.source != expected.source || quote.destination != expected.destination {
        return Err(CorrelationRejection::TupleMismatch);
    }
    if quote.protocol != expected.protocol {
        return Err(CorrelationRejection::ProtocolMismatch);
    }
    let strength = match quote.transport {
        QuotedTransport::Tcp {
            source_port,
            destination_port,
            sequence_number,
            ..
        } => {
            require_outbound_ports(expected, source_port, destination_port)?;
            if sequence_number != token.tcp_sequence() {
                return Err(CorrelationRejection::TokenMismatch);
            }
            EvidenceStrength::StrongTcpSequence32
        }
        QuotedTransport::Udp {
            source_port,
            destination_port,
            payload_prefix,
            ..
        } => {
            require_outbound_ports(expected, source_port, destination_port)?;
            classify_payload_prefix(payload_prefix, token)?
        }
        QuotedTransport::IcmpEcho {
            identifier,
            sequence,
            payload_prefix,
            ..
        } => {
            if identifier != expected.icmp_identifier || sequence != expected.icmp_sequence {
                return Err(CorrelationRejection::TupleMismatch);
            }
            classify_payload_prefix(payload_prefix, token)?
        }
        QuotedTransport::NonFirstFragment { .. } => {
            return Err(CorrelationRejection::FragmentedQuote);
        }
        QuotedTransport::Insufficient { .. } => {
            return Err(CorrelationRejection::InsufficientQuote);
        }
        QuotedTransport::Opaque { .. } => {
            return Err(CorrelationRejection::ProtocolMismatch);
        }
    };
    Ok(CorrelationEvidence {
        kind: CorrelationEvidenceKind::IcmpErrorQuote,
        strength,
    })
}

/// Labels an already protocol-validated ARP discovery response.
#[must_use]
pub const fn classify_arp_reply() -> CorrelationEvidence {
    CorrelationEvidence {
        kind: CorrelationEvidenceKind::ArpReply,
        strength: EvidenceStrength::TupleCorrelatedUnauthenticated,
    }
}

/// Labels an already protocol-validated Neighbor Advertisement response.
#[must_use]
pub const fn classify_neighbor_advertisement() -> CorrelationEvidence {
    CorrelationEvidence {
        kind: CorrelationEvidenceKind::NeighborAdvertisement,
        strength: EvidenceStrength::TupleCorrelatedUnauthenticated,
    }
}

/// Source identifier retained while a probe is outstanding or in late grace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CorrelationLeaseKey {
    family: u8,
    protocol: IpProtocol,
    source_identifier: u16,
}

impl CorrelationLeaseKey {
    /// Selects source port for TCP/UDP and identifier for ICMP.
    #[must_use]
    pub const fn for_probe(identity: ProbeIdentity) -> Option<Self> {
        let family = match identity.source {
            IpAddress::V4(_) => 4,
            IpAddress::V6(_) => 6,
        };
        let source_identifier = match identity.protocol.get() {
            6 | 17 => identity.source_port.get(),
            1 | 58 => identity.icmp_identifier,
            _ => return None,
        };
        Some(Self {
            family,
            protocol: identity.protocol,
            source_identifier,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaseState {
    Outstanding,
    Grace { reusable_at: u64 },
}

/// Bounded source-port/identifier reuse protection driven by caller monotonic time.
#[derive(Debug)]
pub struct CorrelationReuseGuard {
    entries: BTreeMap<CorrelationLeaseKey, LeaseState>,
    capacity: usize,
    grace_duration: u64,
}

impl CorrelationReuseGuard {
    /// Creates a bounded guard; time units are defined by the scanner runtime.
    ///
    /// # Errors
    ///
    /// Rejects zero or globally excessive capacity.
    pub fn new(capacity: usize, grace_duration: u64) -> Result<Self, ReuseGuardError> {
        if capacity == 0 || capacity > MAX_CORRELATION_LEASES {
            return Err(ReuseGuardError::InvalidCapacity);
        }
        Ok(Self {
            entries: BTreeMap::new(),
            capacity,
            grace_duration,
        })
    }

    /// Reserves an identifier only when no outstanding/grace ambiguity exists.
    ///
    /// # Errors
    ///
    /// Reports unsupported protocols, conflicts, or bounded capacity exhaustion.
    pub fn reserve(
        &mut self,
        identity: ProbeIdentity,
        now: u64,
    ) -> Result<CorrelationLeaseKey, ReuseGuardError> {
        self.prune(now);
        let key =
            CorrelationLeaseKey::for_probe(identity).ok_or(ReuseGuardError::UnsupportedProtocol)?;
        if self.entries.contains_key(&key) {
            return Err(ReuseGuardError::Conflict);
        }
        if self.entries.len() == self.capacity {
            return Err(ReuseGuardError::CapacityExhausted);
        }
        self.entries.insert(key, LeaseState::Outstanding);
        Ok(key)
    }

    /// Moves an outstanding identifier into late-response grace.
    ///
    /// # Errors
    ///
    /// Reports unknown/non-outstanding keys or monotonic deadline overflow.
    pub fn complete(&mut self, key: CorrelationLeaseKey, now: u64) -> Result<(), ReuseGuardError> {
        if self.entries.get(&key) != Some(&LeaseState::Outstanding) {
            return Err(ReuseGuardError::NotOutstanding);
        }
        let reusable_at = now
            .checked_add(self.grace_duration)
            .ok_or(ReuseGuardError::DeadlineOverflow)?;
        self.entries.insert(key, LeaseState::Grace { reusable_at });
        Ok(())
    }

    /// Removes grace entries whose caller-supplied monotonic deadline passed.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(
            |_, state| !matches!(state, LeaseState::Grace { reusable_at } if now >= *reusable_at),
        );
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Stable reuse-guard failures for scheduler policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReuseGuardError {
    InvalidCapacity,
    UnsupportedProtocol,
    Conflict,
    CapacityExhausted,
    NotOutstanding,
    DeadlineOverflow,
}

impl fmt::Display for ReuseGuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "correlation reuse guard: {self:?}")
    }
}

impl std::error::Error for ReuseGuardError {}

fn canonical_addresses(source: IpAddress, destination: IpAddress) -> (u8, [u8; 16], [u8; 16]) {
    match (source, destination) {
        (IpAddress::V4(source), IpAddress::V4(destination)) => {
            let mut source_bytes = [0_u8; 16];
            source_bytes[12..].copy_from_slice(&source.octets());
            let mut destination_bytes = [0_u8; 16];
            destination_bytes[12..].copy_from_slice(&destination.octets());
            (4, source_bytes, destination_bytes)
        }
        (IpAddress::V6(source), IpAddress::V6(destination)) => {
            (6, source.octets(), destination.octets())
        }
        _ => unreachable!("ProbeIdentity construction enforces one address family"),
    }
}

fn reverse_tuple_matches(expected: ProbeIdentity, tuple: ResponseTuple) -> bool {
    tuple.source == expected.destination
        && tuple.destination == expected.source
        && tuple.source_port == expected.destination_port
        && tuple.destination_port == expected.source_port
}

fn require_outbound_ports(
    expected: ProbeIdentity,
    source: Port,
    destination: Port,
) -> Result<(), CorrelationRejection> {
    if source != expected.source_port || destination != expected.destination_port {
        return Err(CorrelationRejection::TupleMismatch);
    }
    Ok(())
}

fn classify_payload_prefix(
    prefix: &[u8],
    token: CorrelationToken,
) -> Result<EvidenceStrength, CorrelationRejection> {
    if prefix.len() < 16 {
        return Ok(EvidenceStrength::TruncatedQuote);
    }
    if !token.payload_matches(&prefix[..16]) {
        return Err(CorrelationRejection::TokenMismatch);
    }
    Ok(EvidenceStrength::StrongPayload128)
}
