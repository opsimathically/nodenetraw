use std::{
    io,
    net::IpAddr,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use netlink_packet_core::{
    DefaultNla, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    address::AddressMessage,
    link::LinkMessage,
    neighbour::NeighbourMessage,
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage},
    rule::RuleMessage,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::{
    CancellationToken, IncompleteReason, MAX_BUFFERED_NOTIFICATION_BYTES,
    MAX_BUFFERED_NOTIFICATIONS, MAX_NETLINK_DATAGRAM_BYTES, MAX_RESYNC_BACKOFF,
    MAX_ROUTE_QUERY_ATTEMPTS, MAX_ROUTE_QUERY_DEADLINE, MAX_SNAPSHOT_ATTEMPTS, NetworkSnapshot,
    RefreshOutcome, RoutePlan, RouteQuery, RouteUnusableReason, SnapshotCompleteness,
    SnapshotError, SnapshotResource,
    decoder::{BufferedNotification, DecodedDump, DumpCollector, decode_notification_datagram},
    normalize::{NormalizedParts, normalize_route_message},
    planner::{kernel_unusable_plan, plan_route},
    preflight::DumpKind,
    socket_options::{netns_cookie, set_receive_timeout},
};

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_RESYNC_BACKOFF: Duration = Duration::from_millis(100);
const ROUTE_MULTICAST_GROUPS: [u32; 7] = [1, 3, 5, 7, 8, 9, 11];
const IPV6_RULE_MULTICAST_GROUP: u32 = 19;

/// A serialized, read-only `NETLINK_ROUTE` view anchored to its creation namespace.
///
/// The owned descriptor is never recreated during snapshots, so moving the calling
/// thread to another namespace does not retarget this context. Mutable access is
/// required to prevent concurrent request sequences on the descriptor.
pub struct RouteContext {
    socket: Socket,
    local_port: u32,
    next_sequence: u32,
    generation: u64,
    netns_cookie: Option<u64>,
    current: Option<NetworkSnapshot>,
    notifications: Vec<BufferedNotification>,
    notification_bytes: usize,
    invalidated: bool,
    resync_failures: u32,
    next_resync: Option<Instant>,
}

impl RouteContext {
    /// Opens and binds a close-on-exec route-netlink descriptor in the current namespace.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] when the descriptor cannot be created, bound, or
    /// configured, or when its namespace identity cannot be queried safely.
    pub fn new() -> Result<Self, SnapshotError> {
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|error| SnapshotError::io("create NETLINK_ROUTE socket", error))?;
        let local = socket
            .bind_auto()
            .map_err(|error| SnapshotError::io("bind NETLINK_ROUTE socket", error))?;
        for group in ROUTE_MULTICAST_GROUPS
            .into_iter()
            .chain([IPV6_RULE_MULTICAST_GROUP])
        {
            socket
                .add_membership(group)
                .map_err(|error| SnapshotError::io("subscribe NETLINK_ROUTE group", error))?;
        }
        socket
            .set_rx_buf_sz(MAX_NETLINK_DATAGRAM_BYTES)
            .map_err(|error| SnapshotError::io("set NETLINK_ROUTE receive buffer", error))?;
        set_receive_timeout(socket.as_raw_fd(), RECEIVE_TIMEOUT)
            .map_err(|error| SnapshotError::io("set NETLINK_ROUTE receive timeout", error))?;
        if let Err(error) = socket.set_netlink_get_strict_chk(true)
            && !is_unsupported_socket_option(&error)
        {
            return Err(SnapshotError::io(
                "enable strict NETLINK_ROUTE checking",
                error,
            ));
        }
        let netns_cookie = netns_cookie(socket.as_raw_fd())
            .map_err(|error| SnapshotError::io("read network namespace cookie", error))?;
        Ok(Self {
            socket,
            local_port: local.port_number(),
            next_sequence: 1,
            generation: 0,
            netns_cookie,
            current: None,
            notifications: Vec::new(),
            notification_bytes: 0,
            invalidated: false,
            resync_failures: 0,
            next_resync: None,
        })
    }

    /// Captures one complete immutable view, retrying interrupted/coherence failures.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] when a bounded dump fails, input is malformed or
    /// exceeds a ceiling, or three attempts cannot produce a coherent snapshot.
    pub fn snapshot(&mut self) -> Result<NetworkSnapshot, SnapshotError> {
        self.invalidated = true;
        self.clear_notifications();
        let snapshot = with_snapshot_retries(|| self.snapshot_once())?;
        self.current = Some(snapshot.clone());
        self.invalidated = false;
        self.resync_failures = 0;
        self.next_resync = None;
        Ok(snapshot)
    }

    /// Returns the most recently published complete generation, if initialized.
    #[must_use]
    pub const fn current_snapshot(&self) -> Option<&NetworkSnapshot> {
        if self.invalidated {
            None
        } else {
            self.current.as_ref()
        }
    }

    /// Drains subscribed changes without blocking and publishes one atomic generation.
    ///
    /// A malformed or overflowed notification stream invalidates the old generation
    /// and starts at most one bounded full resynchronization. Repeated failures are
    /// rate-limited with exponential backoff.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] when notification decoding, application, or a due
    /// full resynchronization fails.
    pub fn refresh(&mut self) -> Result<RefreshOutcome, SnapshotError> {
        if self.current.is_none() {
            return self.snapshot().map(RefreshOutcome::Published);
        }
        if let Err(error) = self.drain_notifications() {
            self.invalidated = true;
            return self.resync_after(error);
        }
        if self.invalidated {
            return self.resync_if_due();
        }
        if self.notifications.is_empty() {
            return Ok(RefreshOutcome::Unchanged {
                generation: self.generation,
            });
        }
        match self.publish_notifications() {
            Ok(snapshot) => Ok(RefreshOutcome::Published(snapshot)),
            Err(error) => {
                self.invalidated = true;
                self.resync_after(error)
            }
        }
    }

    /// Asks Linux to resolve one policy-aware destination and joins it to one generation.
    ///
    /// Linux, rather than this crate, selects policy rules and ECMP. If subscribed
    /// changes invalidate the captured generation, the complete query is retried up
    /// to three times within its monotonic deadline.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] for invalid selectors, cancellation, deadline expiry,
    /// unavailable complete context, malformed kernel replies, or exhausted retries.
    pub fn resolve_route(
        &mut self,
        query: &RouteQuery,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RoutePlan, SnapshotError> {
        validate_query(query)?;
        let deadline = Instant::now()
            .checked_add(query.deadline)
            .ok_or(SnapshotError::DeadlineExceeded)?;
        for attempt in 1..=MAX_ROUTE_QUERY_ATTEMPTS {
            check_query_control(deadline, cancellation)?;
            match self.refresh()? {
                RefreshOutcome::Backoff { .. } => return Err(SnapshotError::ContextUnavailable),
                RefreshOutcome::Unchanged { .. } | RefreshOutcome::Published(_) => {}
            }
            let captured = self
                .current_snapshot()
                .cloned()
                .ok_or(SnapshotError::ContextUnavailable)?;
            let result = self.query_once(query, deadline, cancellation);
            let result = match result {
                Ok(value) => value,
                Err(error) => {
                    if let Some(reason) = kernel_unusable_reason(&error) {
                        QueryResult::Unusable(reason)
                    } else {
                        if query_failure_invalidates_context(&error) {
                            self.invalidated = true;
                            self.resync_if_due()?;
                        } else if matches!(
                            &error,
                            SnapshotError::Cancelled | SnapshotError::DeadlineExceeded
                        ) {
                            // A reply may still arrive after an abandoned request;
                            // require a clean resync before publishing this context again.
                            self.invalidated = true;
                        }
                        return Err(error);
                    }
                }
            };
            check_query_control(deadline, cancellation)?;
            if let Err(error) = self.drain_notifications() {
                self.invalidated = true;
                let _ = self.resync_after(error)?;
            } else if !self.notifications.is_empty() && self.publish_notifications().is_err() {
                self.invalidated = true;
                let _ = self.resync_if_due()?;
            }
            let current_generation = self
                .current_snapshot()
                .map(|value| value.generation)
                .ok_or(SnapshotError::ContextUnavailable)?;
            if current_generation != captured.generation {
                if attempt == MAX_ROUTE_QUERY_ATTEMPTS {
                    return Err(
                        SnapshotError::incomplete(IncompleteReason::GenerationChanged)
                            .with_attempts(attempt),
                    );
                }
                continue;
            }
            return Ok(match result {
                QueryResult::Route(route) => plan_route(&captured, query.destination, &route),
                QueryResult::Unusable(reason) => {
                    kernel_unusable_plan(&captured, query.destination, reason)
                }
            });
        }
        unreachable!("the bounded route-query loop always returns")
    }

    fn snapshot_once(&mut self) -> Result<NetworkSnapshot, SnapshotError> {
        self.clear_notifications();
        let mut parts = NormalizedParts::default();
        self.push_dump(&mut parts, DumpRequest::Link)?;
        self.push_dump(&mut parts, DumpRequest::Address)?;
        for family in [AddressFamily::Inet, AddressFamily::Inet6] {
            self.push_dump(&mut parts, DumpRequest::Route(family))?;
            self.push_dump(&mut parts, DumpRequest::Rule(family))?;
            self.push_dump(&mut parts, DumpRequest::Neighbor(family))?;
        }
        self.drain_notifications()?;
        parts.apply_notifications(std::mem::take(&mut self.notifications))?;
        self.notification_bytes = 0;
        let parts = parts.finish()?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| SnapshotError::decode("snapshot generation", "counter overflow"))?;
        self.generation = generation;
        Ok(NetworkSnapshot {
            generation,
            completeness: SnapshotCompleteness::Complete,
            netns_cookie: self.netns_cookie,
            interfaces: parts.interfaces,
            addresses: parts.addresses,
            routes: parts.routes,
            rules: parts.rules,
            neighbors: parts.neighbors,
        })
    }

    fn push_dump(
        &mut self,
        parts: &mut NormalizedParts,
        request: DumpRequest,
    ) -> Result<(), SnapshotError> {
        let decoded = self.dump(request)?;
        parts.push_messages(decoded.messages)?;
        self.buffer_notifications(decoded.notifications)
    }

    fn dump(&mut self, request: DumpRequest) -> Result<DecodedDump, SnapshotError> {
        set_receive_timeout(self.socket.as_raw_fd(), RECEIVE_TIMEOUT)
            .map_err(|error| SnapshotError::io("set netlink dump timeout", error))?;
        let sequence = self.take_sequence();
        let kind = request.kind();
        let bytes = request.serialize(sequence, self.local_port);
        let sent = self
            .socket
            .send_to(&bytes, &SocketAddr::new(0, 0), 0)
            .map_err(|error| SnapshotError::io("send NETLINK_ROUTE dump request", error))?;
        if sent != bytes.len() {
            return Err(SnapshotError::io(
                "send NETLINK_ROUTE dump request",
                io::Error::new(io::ErrorKind::WriteZero, "partial netlink datagram send"),
            ));
        }

        let mut collector = DumpCollector::new(kind, sequence, self.local_port);
        let mut buffer = vec![0_u8; MAX_NETLINK_DATAGRAM_BYTES];
        let deadline = Instant::now()
            .checked_add(RECEIVE_TIMEOUT)
            .ok_or_else(|| SnapshotError::decode("netlink dump deadline", "clock overflow"))?;
        loop {
            if Instant::now() >= deadline {
                return collector.finish();
            }
            let received = self.socket.recv_from(&mut &mut buffer[..], libc::MSG_TRUNC);
            let (length, sender) = match received {
                Ok(value) => value,
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    return Err(SnapshotError::incomplete(
                        IncompleteReason::ReceiveBufferOverflow,
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return collector.finish();
                }
                Err(error) => {
                    return Err(SnapshotError::io(
                        "receive NETLINK_ROUTE dump response",
                        error,
                    ));
                }
            };
            if length > buffer.len() {
                return Err(SnapshotError::incomplete(
                    IncompleteReason::DatagramTruncated,
                ));
            }
            if collector.ingest_datagram(
                &buffer[..length],
                sender.port_number(),
                sender.multicast_groups(),
            )? {
                return collector.finish();
            }
        }
    }

    fn query_once(
        &mut self,
        query: &RouteQuery,
        deadline: Instant,
        cancellation: Option<&CancellationToken>,
    ) -> Result<QueryResult, SnapshotError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(SnapshotError::DeadlineExceeded)?
            .min(RECEIVE_TIMEOUT);
        set_receive_timeout(
            self.socket.as_raw_fd(),
            remaining.max(Duration::from_millis(1)),
        )
        .map_err(|error| SnapshotError::io("set route-query timeout", error))?;
        let sequence = self.take_sequence();
        let message = route_query_message(query);
        let bytes = serialize_request(message, NLM_F_REQUEST, sequence, self.local_port);
        let sent = self
            .socket
            .send_to(&bytes, &SocketAddr::new(0, 0), 0)
            .map_err(|error| SnapshotError::io("send RTM_GETROUTE request", error))?;
        if sent != bytes.len() {
            return Err(SnapshotError::io(
                "send RTM_GETROUTE request",
                io::Error::new(io::ErrorKind::WriteZero, "partial netlink datagram send"),
            ));
        }
        let mut collector = DumpCollector::new(DumpKind::Route, sequence, self.local_port);
        let mut buffer = vec![0_u8; MAX_NETLINK_DATAGRAM_BYTES];
        loop {
            check_query_control(deadline, cancellation)?;
            let received = self.socket.recv_from(&mut &mut buffer[..], libc::MSG_TRUNC);
            let (length, sender) = match received {
                Ok(value) => value,
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    self.invalidated = true;
                    return Err(SnapshotError::incomplete(
                        IncompleteReason::ReceiveBufferOverflow,
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    check_query_control(deadline, cancellation)?;
                    continue;
                }
                Err(error) => {
                    return Err(SnapshotError::io("receive RTM_GETROUTE response", error));
                }
            };
            if length > buffer.len() {
                self.invalidated = true;
                return Err(SnapshotError::incomplete(
                    IncompleteReason::DatagramTruncated,
                ));
            }
            let ingested = collector.ingest_datagram(
                &buffer[..length],
                sender.port_number(),
                sender.multicast_groups(),
            );
            if let Err(error) = ingested {
                self.buffer_notifications(collector.take_notifications())?;
                return Err(error);
            }
            if collector.query_complete() {
                let mut decoded = collector.finish_query()?;
                self.buffer_notifications(std::mem::take(&mut decoded.notifications))?;
                let message = decoded.messages.pop().ok_or_else(|| {
                    SnapshotError::incomplete(IncompleteReason::UnexpectedMessage)
                })?;
                let RouteNetlinkMessage::NewRoute(message) = message else {
                    return Err(SnapshotError::incomplete(
                        IncompleteReason::UnexpectedMessage,
                    ));
                };
                return normalize_route_message(message).map(QueryResult::Route);
            }
        }
    }

    fn drain_notifications(&mut self) -> Result<(), SnapshotError> {
        let mut buffer = vec![0_u8; MAX_NETLINK_DATAGRAM_BYTES];
        loop {
            let received = self
                .socket
                .recv_from(&mut &mut buffer[..], libc::MSG_DONTWAIT | libc::MSG_TRUNC);
            let (length, sender) = match received {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    self.invalidated = true;
                    return Err(SnapshotError::incomplete(
                        IncompleteReason::ReceiveBufferOverflow,
                    ));
                }
                Err(error) => {
                    self.invalidated = true;
                    return Err(SnapshotError::io(
                        "drain NETLINK_ROUTE notifications",
                        error,
                    ));
                }
            };
            if length > buffer.len() {
                self.invalidated = true;
                return Err(SnapshotError::incomplete(
                    IncompleteReason::DatagramTruncated,
                ));
            }
            let notifications = decode_notification_datagram(
                &buffer[..length],
                sender.port_number(),
                sender.multicast_groups(),
            )?;
            self.buffer_notifications(notifications)?;
        }
    }

    fn buffer_notifications(
        &mut self,
        notifications: Vec<BufferedNotification>,
    ) -> Result<(), SnapshotError> {
        for notification in notifications {
            let total = self
                .notification_bytes
                .checked_add(notification.bytes)
                .ok_or(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::BufferedNotificationBytes,
                    actual: usize::MAX,
                    maximum: MAX_BUFFERED_NOTIFICATION_BYTES,
                })?;
            if total > MAX_BUFFERED_NOTIFICATION_BYTES {
                self.invalidated = true;
                return Err(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::BufferedNotificationBytes,
                    actual: total,
                    maximum: MAX_BUFFERED_NOTIFICATION_BYTES,
                });
            }
            if self.notifications.len() == MAX_BUFFERED_NOTIFICATIONS {
                self.invalidated = true;
                return Err(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::BufferedNotifications,
                    actual: self.notifications.len() + 1,
                    maximum: MAX_BUFFERED_NOTIFICATIONS,
                });
            }
            self.notification_bytes = total;
            self.notifications.push(notification);
        }
        Ok(())
    }

    fn clear_notifications(&mut self) {
        self.notifications.clear();
        self.notification_bytes = 0;
    }

    fn publish_notifications(&mut self) -> Result<NetworkSnapshot, SnapshotError> {
        let current = self
            .current
            .clone()
            .ok_or(SnapshotError::ContextUnavailable)?;
        let netns_cookie = current.netns_cookie;
        let mut parts = NormalizedParts::from_snapshot(current)?;
        parts.apply_notifications(std::mem::take(&mut self.notifications))?;
        self.notification_bytes = 0;
        let parts = parts.finish()?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| SnapshotError::decode("snapshot generation", "counter overflow"))?;
        let snapshot = NetworkSnapshot {
            generation,
            completeness: SnapshotCompleteness::Complete,
            netns_cookie,
            interfaces: parts.interfaces,
            addresses: parts.addresses,
            routes: parts.routes,
            rules: parts.rules,
            neighbors: parts.neighbors,
        };
        self.generation = generation;
        self.current = Some(snapshot.clone());
        Ok(snapshot)
    }

    fn resync_if_due(&mut self) -> Result<RefreshOutcome, SnapshotError> {
        if let Some(not_before) = self.next_resync
            && let Some(retry_after) = not_before.checked_duration_since(Instant::now())
        {
            return Ok(RefreshOutcome::Backoff { retry_after });
        }
        match self.snapshot() {
            Ok(snapshot) => Ok(RefreshOutcome::Published(snapshot)),
            Err(error) => {
                self.record_resync_failure();
                Err(error)
            }
        }
    }

    fn resync_after(&mut self, original: SnapshotError) -> Result<RefreshOutcome, SnapshotError> {
        if self.next_resync.is_some_and(|value| value > Instant::now()) {
            return self.resync_if_due();
        }
        if let Ok(snapshot) = self.snapshot() {
            Ok(RefreshOutcome::Published(snapshot))
        } else {
            self.record_resync_failure();
            Err(original)
        }
    }

    fn record_resync_failure(&mut self) {
        self.invalidated = true;
        self.resync_failures = self.resync_failures.saturating_add(1);
        let shift = self.resync_failures.saturating_sub(1).min(6);
        let multiplier = 1_u32 << shift;
        let delay = INITIAL_RESYNC_BACKOFF
            .saturating_mul(multiplier)
            .min(MAX_RESYNC_BACKOFF);
        self.next_resync = Instant::now().checked_add(delay);
    }

    fn take_sequence(&mut self) -> u32 {
        let current = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        if self.next_sequence == 0 {
            self.next_sequence = 1;
        }
        current
    }
}

fn with_snapshot_retries<T>(
    mut attempt_snapshot: impl FnMut() -> Result<T, SnapshotError>,
) -> Result<T, SnapshotError> {
    for attempt in 1..=MAX_SNAPSHOT_ATTEMPTS {
        match attempt_snapshot() {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) if error.is_incomplete() && attempt < MAX_SNAPSHOT_ATTEMPTS => {}
            Err(error) => return Err(error.with_attempts(attempt)),
        }
    }
    unreachable!("the bounded snapshot loop always returns")
}

enum QueryResult {
    Route(crate::RouteRecord),
    Unusable(RouteUnusableReason),
}

fn validate_query(query: &RouteQuery) -> Result<(), SnapshotError> {
    if query.deadline.is_zero() || query.deadline > MAX_ROUTE_QUERY_DEADLINE {
        return Err(SnapshotError::InvalidQuery(format!(
            "deadline must be greater than zero and no more than {MAX_ROUTE_QUERY_DEADLINE:?}"
        )));
    }
    if query
        .source
        .is_some_and(|source| source.is_ipv4() != query.destination.is_ipv4())
    {
        return Err(SnapshotError::InvalidQuery(
            "source and destination address families differ".into(),
        ));
    }
    if query.output_interface == Some(0) {
        return Err(SnapshotError::InvalidQuery(
            "output interface must be nonzero".into(),
        ));
    }
    if (query.source_port.is_some() || query.destination_port.is_some())
        && query.ip_protocol.is_none()
    {
        return Err(SnapshotError::InvalidQuery(
            "port selectors require an IP protocol".into(),
        ));
    }
    if is_ipv6_link_local(query.destination) && query.output_interface.is_none() {
        return Err(SnapshotError::InvalidQuery(
            "link-local IPv6 destinations require an output interface".into(),
        ));
    }
    Ok(())
}

fn route_query_message(query: &RouteQuery) -> RouteNetlinkMessage {
    let mut message = RouteMessage::default();
    message.header.address_family = if query.destination.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    message.header.destination_prefix_length = if query.destination.is_ipv4() { 32 } else { 128 };
    // IPv4 requires RTM_F_LOOKUP_TABLE to preserve the table selected by policy
    // routing in the reply. The IPv6 lookup path rejects this IPv4-only flag.
    if query.destination.is_ipv4() {
        message.header.flags.insert(RouteFlags::LookupTable);
    }
    message
        .attributes
        .push(RouteAttribute::Destination(RouteAddress::from(
            query.destination,
        )));
    if let Some(source) = query.source {
        message.header.source_prefix_length = if source.is_ipv4() { 32 } else { 128 };
        message
            .attributes
            .push(RouteAttribute::Source(RouteAddress::from(source)));
    }
    if let Some(index) = query.output_interface {
        message.attributes.push(RouteAttribute::Oif(index));
    }
    if let Some(mark) = query.mark {
        message.attributes.push(RouteAttribute::Mark(mark));
    }
    if let Some(uid) = query.uid {
        message.attributes.push(RouteAttribute::Uid(uid));
    }
    if let Some(protocol) = query.ip_protocol {
        message
            .attributes
            .push(RouteAttribute::Other(DefaultNla::new(27, vec![protocol])));
    }
    if let Some(port) = query.source_port {
        message
            .attributes
            .push(RouteAttribute::Other(DefaultNla::new(
                28,
                port.to_be_bytes().to_vec(),
            )));
    }
    if let Some(port) = query.destination_port {
        message
            .attributes
            .push(RouteAttribute::Other(DefaultNla::new(
                29,
                port.to_be_bytes().to_vec(),
            )));
    }
    RouteNetlinkMessage::GetRoute(message)
}

fn serialize_request(
    message: RouteNetlinkMessage,
    flags: u16,
    sequence: u32,
    local_port: u32,
) -> Vec<u8> {
    let mut message = NetlinkMessage::new(
        NetlinkHeader::default(),
        NetlinkPayload::InnerMessage(message),
    );
    message.header.flags = flags;
    message.header.sequence_number = sequence;
    message.header.port_number = local_port;
    message.finalize();
    let mut bytes = vec![0_u8; message.buffer_len()];
    message.serialize(&mut bytes);
    bytes
}

fn check_query_control(
    deadline: Instant,
    cancellation: Option<&CancellationToken>,
) -> Result<(), SnapshotError> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return Err(SnapshotError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(SnapshotError::DeadlineExceeded);
    }
    Ok(())
}

fn kernel_unusable_reason(error: &SnapshotError) -> Option<RouteUnusableReason> {
    let SnapshotError::Incomplete {
        reason: IncompleteReason::KernelError(code),
        ..
    } = error
    else {
        return None;
    };
    match code.checked_neg()? {
        libc::EACCES | libc::EPERM => Some(RouteUnusableReason::Prohibited),
        libc::EINVAL => Some(RouteUnusableReason::BlackHole),
        libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ESRCH => {
            Some(RouteUnusableReason::Unreachable)
        }
        _ => None,
    }
}

const fn query_failure_invalidates_context(error: &SnapshotError) -> bool {
    match error {
        SnapshotError::Io { .. }
        | SnapshotError::Decode { .. }
        | SnapshotError::LimitExceeded { .. } => true,
        SnapshotError::Incomplete { reason, .. } => {
            !matches!(reason, IncompleteReason::KernelError(_))
        }
        SnapshotError::UnsupportedAddressFamily(_)
        | SnapshotError::InvalidQuery(_)
        | SnapshotError::Cancelled
        | SnapshotError::DeadlineExceeded
        | SnapshotError::ContextUnavailable => false,
    }
}

const fn is_ipv6_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(value) => (value.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

#[derive(Clone, Copy)]
enum DumpRequest {
    Link,
    Address,
    Route(AddressFamily),
    Rule(AddressFamily),
    Neighbor(AddressFamily),
}

impl DumpRequest {
    const fn kind(self) -> DumpKind {
        match self {
            Self::Link => DumpKind::Link,
            Self::Address => DumpKind::Address,
            Self::Route(_) => DumpKind::Route,
            Self::Rule(_) => DumpKind::Rule,
            Self::Neighbor(_) => DumpKind::Neighbor,
        }
    }

    fn message(self) -> RouteNetlinkMessage {
        match self {
            Self::Link => RouteNetlinkMessage::GetLink(LinkMessage::default()),
            Self::Address => RouteNetlinkMessage::GetAddress(AddressMessage::default()),
            Self::Route(family) => {
                let mut message = RouteMessage::default();
                message.header.address_family = family;
                RouteNetlinkMessage::GetRoute(message)
            }
            Self::Rule(family) => {
                let mut message = RuleMessage::default();
                message.header.family = family;
                RouteNetlinkMessage::GetRule(message)
            }
            Self::Neighbor(family) => {
                let mut message = NeighbourMessage::default();
                message.header.family = family;
                RouteNetlinkMessage::GetNeighbour(message)
            }
        }
    }

    fn serialize(self, sequence: u32, local_port: u32) -> Vec<u8> {
        serialize_request(
            self.message(),
            NLM_F_REQUEST | NLM_F_DUMP,
            sequence,
            local_port,
        )
    }
}

fn is_unsupported_socket_option(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOPROTOOPT | libc::EINVAL))
}

#[cfg(test)]
mod tests {
    use super::{
        DumpRequest, route_query_message, serialize_request, validate_query, with_snapshot_retries,
    };
    use crate::{CancellationToken, IncompleteReason, RouteContext, RouteQuery, SnapshotError};
    use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage, route::RouteFlags};

    #[test]
    fn route_lookup_table_flag_is_limited_to_ipv4() {
        let RouteNetlinkMessage::GetRoute(ipv4) =
            route_query_message(&RouteQuery::new("192.0.2.1".parse().unwrap()))
        else {
            panic!("expected an IPv4 route query");
        };
        assert!(ipv4.header.flags.contains(RouteFlags::LookupTable));

        let RouteNetlinkMessage::GetRoute(ipv6) =
            route_query_message(&RouteQuery::new("2001:db8::1".parse().unwrap()))
        else {
            panic!("expected an IPv6 route query");
        };
        assert!(!ipv6.header.flags.contains(RouteFlags::LookupTable));
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_route_selectors() {
        let mut query = RouteQuery::new("192.0.2.1".parse().unwrap());
        query.source = Some("2001:db8::1".parse().unwrap());
        assert!(matches!(
            validate_query(&query),
            Err(SnapshotError::InvalidQuery(_))
        ));

        let mut query = RouteQuery::new("192.0.2.1".parse().unwrap());
        query.destination_port = Some(443);
        assert!(matches!(
            validate_query(&query),
            Err(SnapshotError::InvalidQuery(_))
        ));

        let mut query = RouteQuery::new("fe80::1".parse().unwrap());
        assert!(matches!(
            validate_query(&query),
            Err(SnapshotError::InvalidQuery(_))
        ));
        query.output_interface = Some(7);
        assert!(validate_query(&query).is_ok());

        query.deadline = std::time::Duration::ZERO;
        assert!(matches!(
            validate_query(&query),
            Err(SnapshotError::InvalidQuery(_))
        ));
    }

    #[test]
    fn pre_cancelled_query_does_not_initialize_or_issue_io() {
        let mut context = RouteContext::new().unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            context.resolve_route(
                &RouteQuery::new("127.0.0.1".parse().unwrap()),
                Some(&cancellation)
            ),
            Err(SnapshotError::Cancelled)
        ));
        assert!(context.current_snapshot().is_none());
    }

    #[test]
    fn invalidated_context_resynchronizes_or_reports_bounded_backoff() {
        let mut context = RouteContext::new().unwrap();
        let first = context.snapshot().unwrap();
        context.invalidated = true;
        let outcome = context
            .resync_after(SnapshotError::decode("test", "forced invalidation"))
            .unwrap();
        let crate::RefreshOutcome::Published(second) = outcome else {
            panic!("a healthy forced resync should publish");
        };
        assert!(second.generation > first.generation);
        assert_eq!(
            context.current_snapshot().unwrap().generation,
            second.generation
        );

        for _ in 0..100 {
            context.record_resync_failure();
        }
        let crate::RefreshOutcome::Backoff { retry_after } = context.resync_if_due().unwrap()
        else {
            panic!("a failed context should honor its resync backoff");
        };
        assert!(retry_after <= crate::MAX_RESYNC_BACKOFF);
        assert!(context.current_snapshot().is_none());
    }

    #[test]
    fn request_surface_is_get_and_dump_only() {
        let requests = [
            DumpRequest::Link,
            DumpRequest::Address,
            DumpRequest::Route(AddressFamily::Inet),
            DumpRequest::Rule(AddressFamily::Inet6),
            DumpRequest::Neighbor(AddressFamily::Inet),
        ];
        let expected_types = [18_u16, 22, 26, 34, 30];
        for (request, expected_type) in requests.into_iter().zip(expected_types) {
            let bytes = request.serialize(7, 42);
            assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), expected_type);
            let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
            assert_eq!(flags, NLM_F_REQUEST | NLM_F_DUMP);
        }

        let query = serialize_request(
            route_query_message(&RouteQuery::new("192.0.2.1".parse().unwrap())),
            NLM_F_REQUEST,
            8,
            42,
        );
        assert_eq!(u16::from_ne_bytes([query[4], query[5]]), 26);
        assert_eq!(u16::from_ne_bytes([query[6], query[7]]), NLM_F_REQUEST);
    }

    #[test]
    fn retries_only_incomplete_results_and_stops_at_three() {
        let mut attempts = 0;
        let value = with_snapshot_retries(|| {
            attempts += 1;
            if attempts < 3 {
                Err(SnapshotError::incomplete(IncompleteReason::DumpInterrupted))
            } else {
                Ok(17)
            }
        })
        .unwrap();
        assert_eq!(value, 17);
        assert_eq!(attempts, 3);

        let mut attempts = 0;
        let error = with_snapshot_retries::<()>(|| {
            attempts += 1;
            Err(SnapshotError::incomplete(IncompleteReason::Overrun))
        })
        .unwrap_err();
        assert_eq!(attempts, 3);
        assert!(matches!(
            error,
            SnapshotError::Incomplete {
                reason: IncompleteReason::Overrun,
                attempts: 3
            }
        ));

        let mut attempts = 0;
        assert!(matches!(
            with_snapshot_retries::<()>(|| {
                attempts += 1;
                Err(SnapshotError::decode("test", "malformed"))
            }),
            Err(SnapshotError::Decode { .. })
        ));
        assert_eq!(attempts, 1);
    }
}
