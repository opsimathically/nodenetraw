use netlink_packet_core::{
    NLM_F_DUMP_INTR, NLM_F_MULTIPART, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::RouteNetlinkMessage;

use crate::{
    IncompleteReason, MAX_BUFFERED_NOTIFICATION_BYTES, MAX_BUFFERED_NOTIFICATIONS, MAX_DUMP_BYTES,
    MAX_MESSAGES_PER_DUMP, MAX_NETLINK_DATAGRAM_BYTES, SnapshotError, SnapshotResource,
    preflight::DumpKind, preflight::validate_inner_message,
};

const NETLINK_HEADER_LENGTH: usize = 16;

pub(crate) struct DumpCollector {
    kind: DumpKind,
    expected_sequence: u32,
    local_port: u32,
    message_count: usize,
    byte_count: usize,
    ignored_notifications: usize,
    done: bool,
    saw_single_response: bool,
    messages: Vec<RouteNetlinkMessage>,
    notifications: Vec<BufferedNotification>,
    notification_bytes: usize,
}

impl DumpCollector {
    pub(crate) fn new(kind: DumpKind, expected_sequence: u32, local_port: u32) -> Self {
        Self {
            kind,
            expected_sequence,
            local_port,
            message_count: 0,
            byte_count: 0,
            ignored_notifications: 0,
            done: false,
            saw_single_response: false,
            messages: Vec::new(),
            notifications: Vec::new(),
            notification_bytes: 0,
        }
    }

    pub(crate) fn ingest_datagram(
        &mut self,
        datagram: &[u8],
        sender_port: u32,
        sender_groups: u32,
    ) -> Result<bool, SnapshotError> {
        if self.done {
            return Err(SnapshotError::incomplete(
                IncompleteReason::UnexpectedMessage,
            ));
        }
        if datagram.len() > MAX_NETLINK_DATAGRAM_BYTES {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::DatagramBytes,
                actual: datagram.len(),
                maximum: MAX_NETLINK_DATAGRAM_BYTES,
            });
        }
        self.byte_count =
            self.byte_count
                .checked_add(datagram.len())
                .ok_or(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::DumpBytes,
                    actual: usize::MAX,
                    maximum: MAX_DUMP_BYTES,
                })?;
        if self.byte_count > MAX_DUMP_BYTES {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::DumpBytes,
                actual: self.byte_count,
                maximum: MAX_DUMP_BYTES,
            });
        }
        if sender_port != 0 {
            return Err(SnapshotError::incomplete(IncompleteReason::SenderNotKernel));
        }
        let mut offset = 0_usize;
        while offset < datagram.len() {
            let remaining = datagram.len() - offset;
            if remaining < NETLINK_HEADER_LENGTH {
                return Err(SnapshotError::decode(
                    "netlink message header",
                    "datagram ends with a truncated header",
                ));
            }
            let length = usize::try_from(u32::from_ne_bytes(
                datagram[offset..offset + 4]
                    .try_into()
                    .expect("checked four-byte netlink length"),
            ))
            .map_err(|error| SnapshotError::decode("netlink message length", error))?;
            if length < NETLINK_HEADER_LENGTH {
                return Err(SnapshotError::decode(
                    "netlink message length",
                    "message length is smaller than its header",
                ));
            }
            let end = offset.checked_add(length).ok_or_else(|| {
                SnapshotError::decode("netlink message length", "offset overflow")
            })?;
            if end > datagram.len() {
                return Err(SnapshotError::decode(
                    "netlink message length",
                    "message extends beyond its datagram",
                ));
            }
            self.message_count += 1;
            if self.message_count > MAX_MESSAGES_PER_DUMP {
                return Err(SnapshotError::LimitExceeded {
                    resource: SnapshotResource::DumpMessages,
                    actual: self.message_count,
                    maximum: MAX_MESSAGES_PER_DUMP,
                });
            }
            let message_bytes = &datagram[offset..end];
            self.ingest_message(message_bytes, sender_groups)?;
            let aligned = align4(length).ok_or_else(|| {
                SnapshotError::decode("netlink message alignment", "length overflow")
            })?;
            offset = offset.checked_add(aligned).ok_or_else(|| {
                SnapshotError::decode("netlink message alignment", "offset overflow")
            })?;
            if offset > datagram.len() {
                return Err(SnapshotError::decode(
                    "netlink message padding",
                    "aligned message extends beyond its datagram",
                ));
            }
            if self.done && offset != datagram.len() {
                return Err(SnapshotError::incomplete(
                    IncompleteReason::UnexpectedMessage,
                ));
            }
        }
        Ok(self.done)
    }

    fn ingest_message(&mut self, bytes: &[u8], sender_groups: u32) -> Result<(), SnapshotError> {
        let message_type = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        let sequence = u32::from_ne_bytes(bytes[8..12].try_into().expect("checked sequence"));
        let port = u32::from_ne_bytes(bytes[12..16].try_into().expect("checked port"));
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(SnapshotError::incomplete(IncompleteReason::DumpInterrupted));
        }
        // Multicast notifications can retain the sequence of the userspace
        // request that caused the change; the sender group, not sequence zero
        // alone, is the authoritative discriminator from our unicast reply.
        if sequence == 0 || sender_groups != 0 {
            self.ignored_notifications += 1;
            return self.ingest_notification(bytes, message_type, port);
        }
        if sequence != self.expected_sequence {
            return Err(SnapshotError::incomplete(
                IncompleteReason::SequenceMismatch,
            ));
        }
        if port != 0 && port != self.local_port {
            return Err(SnapshotError::incomplete(
                IncompleteReason::HeaderPortMismatch,
            ));
        }
        if !matches!(
            message_type,
            NLMSG_DONE | NLMSG_ERROR | NLMSG_NOOP | NLMSG_OVERRUN
        ) && message_type != self.kind.response_type()
        {
            return Err(SnapshotError::incomplete(
                IncompleteReason::UnexpectedMessage,
            ));
        }
        if message_type == self.kind.response_type() {
            validate_inner_message(bytes, self.kind)?;
            if flags & NLM_F_MULTIPART == 0 {
                self.saw_single_response = true;
            }
        }
        let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
            .map_err(|error| SnapshotError::decode("netlink route message", error))?;
        match message.payload {
            NetlinkPayload::Done(done) => {
                if done.code != 0 {
                    return Err(SnapshotError::incomplete(IncompleteReason::KernelError(
                        done.code,
                    )));
                }
                self.done = true;
            }
            NetlinkPayload::Error(error) => {
                if let Some(code) = error.code {
                    if code.get() == -libc::ENOBUFS {
                        return Err(SnapshotError::incomplete(
                            IncompleteReason::ReceiveBufferOverflow,
                        ));
                    }
                    return Err(SnapshotError::incomplete(IncompleteReason::KernelError(
                        code.get(),
                    )));
                }
            }
            NetlinkPayload::Noop => {}
            NetlinkPayload::Overrun(_) => {
                return Err(SnapshotError::incomplete(IncompleteReason::Overrun));
            }
            NetlinkPayload::InnerMessage(message) => self.messages.push(message),
            _ => {
                return Err(SnapshotError::incomplete(
                    IncompleteReason::UnexpectedMessage,
                ));
            }
        }
        Ok(())
    }

    fn ingest_notification(
        &mut self,
        bytes: &[u8],
        message_type: u16,
        _port: u32,
    ) -> Result<(), SnapshotError> {
        // The netlink header port identifies the userspace request that caused
        // a multicast change and can therefore be nonzero. The recvmsg sender
        // sockaddr was already required to be the kernel before reaching here.
        if message_type == NLMSG_OVERRUN {
            return Err(SnapshotError::incomplete(IncompleteReason::Overrun));
        }
        if message_type == NLMSG_ERROR {
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
                .map_err(|error| SnapshotError::decode("netlink notification error", error))?;
            if let NetlinkPayload::Error(error) = message.payload
                && let Some(code) = error.code
            {
                return Err(SnapshotError::incomplete(IncompleteReason::KernelError(
                    code.get(),
                )));
            }
            return Err(SnapshotError::incomplete(
                IncompleteReason::UnexpectedMessage,
            ));
        }
        let kind = DumpKind::from_notification_type(message_type)
            .ok_or_else(|| SnapshotError::incomplete(IncompleteReason::UnexpectedMessage))?;
        validate_inner_message(bytes, kind)?;
        let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
            .map_err(|error| SnapshotError::decode("netlink route notification", error))?;
        let NetlinkPayload::InnerMessage(message) = message.payload else {
            return Err(SnapshotError::incomplete(
                IncompleteReason::UnexpectedMessage,
            ));
        };
        let total = self.notification_bytes.checked_add(bytes.len()).ok_or(
            SnapshotError::LimitExceeded {
                resource: SnapshotResource::BufferedNotificationBytes,
                actual: usize::MAX,
                maximum: MAX_BUFFERED_NOTIFICATION_BYTES,
            },
        )?;
        if total > MAX_BUFFERED_NOTIFICATION_BYTES {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::BufferedNotificationBytes,
                actual: total,
                maximum: MAX_BUFFERED_NOTIFICATION_BYTES,
            });
        }
        if self.notifications.len() == MAX_BUFFERED_NOTIFICATIONS {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::BufferedNotifications,
                actual: self.notifications.len() + 1,
                maximum: MAX_BUFFERED_NOTIFICATIONS,
            });
        }
        self.notification_bytes = total;
        self.notifications.push(BufferedNotification {
            message,
            bytes: bytes.len(),
        });
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<DecodedDump, SnapshotError> {
        if !self.done {
            return Err(SnapshotError::incomplete(
                IncompleteReason::MissingTerminator,
            ));
        }
        Ok(DecodedDump {
            messages: self.messages,
            ignored_notifications: self.ignored_notifications,
            notifications: self.notifications,
        })
    }

    pub(crate) fn query_complete(&self) -> bool {
        self.done || (self.saw_single_response && self.messages.len() == 1)
    }

    pub(crate) fn finish_query(self) -> Result<DecodedDump, SnapshotError> {
        if !self.done && !self.saw_single_response {
            return Err(SnapshotError::incomplete(
                IncompleteReason::MissingTerminator,
            ));
        }
        if self.messages.len() != 1 {
            return Err(SnapshotError::incomplete(
                IncompleteReason::UnexpectedMessage,
            ));
        }
        Ok(DecodedDump {
            messages: self.messages,
            ignored_notifications: self.ignored_notifications,
            notifications: self.notifications,
        })
    }

    pub(crate) fn into_notifications(self) -> Vec<BufferedNotification> {
        self.notifications
    }

    pub(crate) fn take_notifications(&mut self) -> Vec<BufferedNotification> {
        self.notification_bytes = 0;
        std::mem::take(&mut self.notifications)
    }
}

#[derive(Debug)]
pub(crate) struct DecodedDump {
    pub(crate) messages: Vec<RouteNetlinkMessage>,
    #[allow(
        dead_code,
        reason = "sequence-zero traffic is deliberately counted separately"
    )]
    pub(crate) ignored_notifications: usize,
    pub(crate) notifications: Vec<BufferedNotification>,
}

#[derive(Debug)]
pub(crate) struct BufferedNotification {
    pub(crate) message: RouteNetlinkMessage,
    pub(crate) bytes: usize,
}

pub(crate) fn decode_notification_datagram(
    datagram: &[u8],
    sender_port: u32,
    sender_groups: u32,
) -> Result<Vec<BufferedNotification>, SnapshotError> {
    let mut collector = DumpCollector::new(DumpKind::Link, u32::MAX, 0);
    collector.ingest_datagram(datagram, sender_port, sender_groups)?;
    Ok(collector.into_notifications())
}

const fn align4(length: usize) -> Option<usize> {
    match length.checked_add(3) {
        Some(value) => Some(value & !3),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use netlink_packet_core::{NLM_F_DUMP_INTR, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN};

    use super::DumpCollector;
    use crate::{
        IncompleteReason, MAX_BUFFERED_NOTIFICATION_BYTES, MAX_DUMP_BYTES, SnapshotError,
        SnapshotResource, preflight::DumpKind,
    };

    const SEQUENCE: u32 = 9;
    const PORT: u32 = 44;

    #[test]
    fn accepts_valid_multipart_dump() {
        let mut datagram = message(16, 0, SEQUENCE, PORT, &link_payload());
        datagram.extend(message(NLMSG_ERROR, 0, SEQUENCE, PORT, &[0; 20]));
        datagram.extend(message(NLMSG_DONE, 0, SEQUENCE, PORT, &[0; 4]));
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert!(collector.ingest_datagram(&datagram, 0, 0).unwrap());
        assert_eq!(collector.finish().unwrap().messages.len(), 1);
    }

    #[test]
    fn keeps_sequence_zero_notifications_out_of_the_dump() {
        let mut datagram = message(16, 0, 0, 0, &link_payload());
        datagram.extend(message(NLMSG_DONE, 0, SEQUENCE, PORT, &[0; 4]));
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert!(collector.ingest_datagram(&datagram, 0, 0).unwrap());
        let decoded = collector.finish().unwrap();
        assert!(decoded.messages.is_empty());
        assert_eq!(decoded.ignored_notifications, 1);
        assert_eq!(decoded.notifications.len(), 1);
    }

    #[test]
    fn accepts_exactly_one_non_multipart_route_query_reply() {
        let mut collector = DumpCollector::new(DumpKind::Route, SEQUENCE, PORT);
        assert!(
            !collector
                .ingest_datagram(&message(24, 0, SEQUENCE, PORT, &route_payload()), 0, 0)
                .unwrap()
        );
        assert!(collector.query_complete());
        assert_eq!(collector.finish_query().unwrap().messages.len(), 1);
    }

    #[test]
    fn accepts_kernel_multicast_with_the_originating_request_identity() {
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert!(
            !collector
                .ingest_datagram(
                    &message(16, 0, SEQUENCE + 77, PORT + 77, &link_payload()),
                    0,
                    1,
                )
                .unwrap()
        );
        assert_eq!(collector.into_notifications().len(), 1);
    }

    #[test]
    fn enforces_notification_byte_ceiling_independently() {
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        collector.notification_bytes = MAX_BUFFERED_NOTIFICATION_BYTES;
        assert!(matches!(
            collector.ingest_datagram(&message(16, 0, 0, 0, &link_payload()), 0, 1),
            Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::BufferedNotificationBytes,
                ..
            })
        ));
    }

    #[test]
    fn rejects_interruption_sequence_sender_and_overrun() {
        let cases = [
            (
                message(16, NLM_F_DUMP_INTR, SEQUENCE, PORT, &link_payload()),
                0,
                IncompleteReason::DumpInterrupted,
            ),
            (
                message(16, 0, SEQUENCE + 1, PORT, &link_payload()),
                0,
                IncompleteReason::SequenceMismatch,
            ),
            (
                message(NLMSG_OVERRUN, 0, SEQUENCE, PORT, &[]),
                0,
                IncompleteReason::Overrun,
            ),
            (
                message(16, 0, SEQUENCE, PORT, &link_payload()),
                55,
                IncompleteReason::SenderNotKernel,
            ),
        ];
        for (datagram, sender, expected) in cases {
            let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
            assert_incomplete(
                &collector.ingest_datagram(&datagram, sender, 0).unwrap_err(),
                expected,
            );
        }
    }

    #[test]
    fn rejects_kernel_errors_and_missing_terminator() {
        let mut error_payload = (-libc::ENOBUFS).to_ne_bytes().to_vec();
        error_payload.extend([0_u8; 16]);
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert_incomplete(
            &collector
                .ingest_datagram(
                    &message(NLMSG_ERROR, 0, SEQUENCE, PORT, &error_payload),
                    0,
                    0,
                )
                .unwrap_err(),
            IncompleteReason::ReceiveBufferOverflow,
        );

        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert!(
            !collector
                .ingest_datagram(&message(16, 0, SEQUENCE, PORT, &link_payload()), 0, 0)
                .unwrap()
        );
        assert_incomplete(
            &collector.finish().unwrap_err(),
            IncompleteReason::MissingTerminator,
        );

        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert_incomplete(
            &collector
                .ingest_datagram(
                    &message(NLMSG_DONE, 0, SEQUENCE, PORT, &(-libc::EINTR).to_ne_bytes()),
                    0,
                    0,
                )
                .unwrap_err(),
            IncompleteReason::KernelError(-libc::EINTR),
        );
    }

    #[test]
    fn rejects_truncated_and_malformed_attribute_data() {
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        let truncated = vec![20_u8, 0, 0, 0, 16, 0, 0, 0, 9, 0, 0, 0, 44, 0, 0, 0];
        assert!(matches!(
            collector.ingest_datagram(&truncated, 0, 0),
            Err(SnapshotError::Decode { .. })
        ));

        let mut payload = link_payload();
        payload.extend([3_u8, 0, 3, 0]);
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        assert!(matches!(
            collector.ingest_datagram(&message(16, 0, SEQUENCE, PORT, &payload), 0, 0),
            Err(SnapshotError::Decode { .. })
        ));
    }

    #[test]
    fn enforces_aggregate_dump_byte_ceiling() {
        let mut collector = DumpCollector::new(DumpKind::Link, SEQUENCE, PORT);
        collector.byte_count = MAX_DUMP_BYTES;
        assert!(matches!(
            collector.ingest_datagram(&message(NLMSG_DONE, 0, SEQUENCE, PORT, &[0; 4]), 0, 0),
            Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::DumpBytes,
                ..
            })
        ));
    }

    fn link_payload() -> Vec<u8> {
        vec![0_u8; 16]
    }

    fn route_payload() -> Vec<u8> {
        vec![0_u8; 12]
    }

    fn message(message_type: u16, flags: u16, sequence: u32, port: u32, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let aligned = (length + 3) & !3;
        let mut output = vec![0_u8; aligned];
        output[0..4].copy_from_slice(&u32::try_from(length).unwrap().to_ne_bytes());
        output[4..6].copy_from_slice(&message_type.to_ne_bytes());
        output[6..8].copy_from_slice(&flags.to_ne_bytes());
        output[8..12].copy_from_slice(&sequence.to_ne_bytes());
        output[12..16].copy_from_slice(&port.to_ne_bytes());
        output[16..length].copy_from_slice(payload);
        output
    }

    fn assert_incomplete(error: &SnapshotError, expected: IncompleteReason) {
        assert!(matches!(
            error,
            SnapshotError::Incomplete {
                reason,
                attempts: 1
            } if *reason == expected
        ));
    }
}
