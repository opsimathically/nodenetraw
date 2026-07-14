use nodenet_protocols::{
    CorrelationEvidenceKind, CorrelationIdentityError, CorrelationRejection, CorrelationReuseGuard,
    EvidenceStrength, Icmpv4Message, Icmpv6Message, Icmpv6Packet, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, NdpContext, NdpMessage, NdpOption, NdpPacket,
    ParseMode, ParsedIcmpv4Message, ParsedIcmpv6Message, ParsedNdpMessage, ParsedNdpOption,
    ParsedNetworkPayload, ParsedTcpOption, Port, ProbeIdentity, ResponseTuple, ReuseGuardError,
    SessionSecret, TcpFlags, TcpOption, TcpSackBlock, TcpSegment, TransportChecksumContext,
    UdpChecksumMode, UdpChecksumStatus, UdpDatagram, UpperLayerState, classify_arp_reply,
    classify_echo_reply, classify_neighbor_advertisement, classify_quoted_response,
    classify_tcp_reply, classify_udp_reply, parse_icmpv4_message, parse_icmpv6_message,
    parse_ndp_message, parse_network_frame, parse_quoted_ip_packet, parse_tcp_segment,
    parse_udp_datagram,
};

const V4_SOURCE: Ipv4Address = Ipv4Address::new([192, 0, 2, 10]);
const V4_DESTINATION: Ipv4Address = Ipv4Address::new([198, 51, 100, 20]);
const V6_SOURCE: Ipv6Address =
    Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const V6_DESTINATION: Ipv6Address =
    Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

fn v4_context() -> TransportChecksumContext {
    TransportChecksumContext::Ipv4 {
        source: V4_SOURCE,
        destination: V4_DESTINATION,
    }
}

fn v6_context() -> TransportChecksumContext {
    TransportChecksumContext::Ipv6 {
        source: V6_SOURCE,
        destination: V6_DESTINATION,
    }
}

#[test]
fn tcp_round_trips_standard_and_unknown_options_for_both_families() {
    let sack = [TcpSackBlock {
        left_edge: 100,
        right_edge: 200,
    }];
    let options = [
        TcpOption::MaximumSegmentSize(1_460),
        TcpOption::WindowScale(7),
        TcpOption::SackPermitted,
        TcpOption::Sack(&sack),
        TcpOption::Timestamp {
            value: 0x0102_0304,
            echo_reply: 0x0506_0708,
        },
        TcpOption::Unknown {
            kind: 30,
            data: &[0xaa, 0xbb],
        },
    ];
    for context in [v4_context(), v6_context()] {
        let segment = TcpSegment {
            checksum_context: context,
            source_port: Port::new(40_000),
            destination_port: Port::new(443),
            sequence_number: 0x1020_3040,
            acknowledgment_number: 0,
            flags: TcpFlags::SYN | TcpFlags::ECE | TcpFlags::CWR,
            window_size: 65_535,
            urgent_pointer: 0,
            options: &options,
            payload: &[],
        };
        let bytes = segment.build().expect("valid TCP SYN");
        let parsed = parse_tcp_segment(&bytes, context).expect("checksum-valid TCP");
        assert_eq!(parsed.sequence_number, segment.sequence_number);
        assert_eq!(parsed.flags, segment.flags);
        assert!(
            parsed
                .options
                .iter()
                .any(|option| matches!(option, ParsedTcpOption::MaximumSegmentSize(1_460)))
        );
        assert!(parsed.options.iter().any(
            |option| matches!(option, ParsedTcpOption::Unknown { kind: 30, data } if data == [0xaa, 0xbb])
        ));
        assert!(etherparse::TcpHeaderSlice::from_slice(&bytes).is_ok());

        let mut corrupt = bytes;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(parse_tcp_segment(&corrupt, context).is_err());
    }
    assert!(TcpOption::WindowScale(15).encoded_test_is_invalid());
}

trait TcpOptionTestExtension {
    fn encoded_test_is_invalid(self) -> bool;
}

impl TcpOptionTestExtension for TcpOption<'_> {
    fn encoded_test_is_invalid(self) -> bool {
        TcpSegment {
            checksum_context: v4_context(),
            source_port: Port::new(1),
            destination_port: Port::new(2),
            sequence_number: 0,
            acknowledgment_number: 0,
            flags: TcpFlags::SYN,
            window_size: 1,
            urgent_pointer: 0,
            options: &[self],
            payload: &[],
        }
        .required_length()
        .is_err()
    }
}

#[test]
fn udp_distinguishes_ipv4_omission_ipv6_requirement_and_owned_payload() {
    let payload = [1, 2, 3, 4, 5];
    let computed = UdpDatagram {
        checksum_context: v6_context(),
        checksum_mode: UdpChecksumMode::Compute,
        source_port: Port::new(53_000),
        destination_port: Port::new(53),
        payload: &payload,
    }
    .build()
    .expect("IPv6 UDP checksum");
    let parsed = parse_udp_datagram(&computed, v6_context()).expect("valid IPv6 UDP");
    assert_eq!(parsed.checksum_status, UdpChecksumStatus::Valid);
    assert_eq!(
        parsed.to_owned().expect("bounded copy").payload.as_slice(),
        payload
    );
    let independent = etherparse::UdpHeader {
        source_port: 53_000,
        destination_port: 53,
        length: u16::try_from(computed.len()).expect("test datagram length"),
        checksum: 0,
    }
    .calc_checksum_ipv6_raw(V6_SOURCE.octets(), V6_DESTINATION.octets(), &payload)
    .expect("independent checksum");
    assert_eq!(u16::from_be_bytes([computed[6], computed[7]]), independent);

    let omitted = UdpDatagram {
        checksum_context: v4_context(),
        checksum_mode: UdpChecksumMode::OmitIpv4,
        source_port: Port::new(1),
        destination_port: Port::new(2),
        payload: &payload,
    }
    .build()
    .expect("IPv4 permits omitted checksum");
    assert_eq!(
        parse_udp_datagram(&omitted, v4_context())
            .expect("valid absent checksum")
            .checksum_status,
        UdpChecksumStatus::NotPresentIpv4
    );
    assert!(
        UdpDatagram {
            checksum_context: v6_context(),
            checksum_mode: UdpChecksumMode::OmitIpv4,
            source_port: Port::new(1),
            destination_port: Port::new(2),
            payload: &[],
        }
        .build()
        .is_err()
    );
    assert!(parse_udp_datagram(&omitted, v6_context()).is_err());
}

#[test]
fn icmpv4_and_icmpv6_echo_and_error_quotes_are_typed() {
    let echo4 = Icmpv4Message::EchoRequest {
        identifier: 0x1234,
        sequence: 7,
        payload: b"phase18",
    }
    .build()
    .expect("ICMPv4 Echo");
    assert_eq!(
        echo4,
        [
            0x08, 0x00, 0x76, 0xb7, 0x12, 0x34, 0x00, 0x07, 0x70, 0x68, 0x61, 0x73, 0x65, 0x31,
            0x38,
        ],
        "matches the existing TypeScript ICMP codec wire representation"
    );
    assert!(matches!(
        parse_icmpv4_message(&echo4).expect("valid echo").message,
        ParsedIcmpv4Message::EchoRequest {
            identifier: 0x1234,
            sequence: 7,
            payload: b"phase18"
        }
    ));

    let udp = UdpDatagram {
        checksum_context: v4_context(),
        checksum_mode: UdpChecksumMode::Compute,
        source_port: Port::new(40_000),
        destination_port: Port::new(33434),
        payload: &[9; 16],
    }
    .build()
    .expect("quoted UDP");
    let quote4 = build_ipv4(IpProtocol::new(17), &udp);
    let error4 = Icmpv4Message::TimeExceeded {
        code: 0,
        quote: &quote4,
    }
    .build()
    .expect("ICMPv4 error");
    assert!(matches!(
        parse_icmpv4_message(&error4).expect("valid error").message,
        ParsedIcmpv4Message::TimeExceeded {
            quoted_packet: Ok(_),
            ..
        }
    ));

    let echo6 = Icmpv6Packet {
        checksum_context: v6_context(),
        message: Icmpv6Message::EchoReply {
            identifier: 55,
            sequence: 66,
            payload: b"token",
        },
    }
    .build()
    .expect("ICMPv6 Echo");
    assert!(matches!(
        parse_icmpv6_message(&echo6, v6_context())
            .expect("valid echo")
            .message,
        ParsedIcmpv6Message::EchoReply {
            identifier: 55,
            sequence: 66,
            payload: b"token"
        }
    ));

    let quote6 = Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        hop_limit: 1,
        source: V6_SOURCE,
        destination: V6_DESTINATION,
        extensions: &[],
        upper_layer_protocol: IpProtocol::new(17),
        payload: &computed_udp_v6(),
    }
    .build()
    .expect("IPv6 quote");
    let error6 = Icmpv6Packet {
        checksum_context: v6_context(),
        message: Icmpv6Message::PacketTooBig {
            mtu: 1_280,
            quote: &quote6,
        },
    }
    .build()
    .expect("ICMPv6 Packet Too Big");
    assert!(matches!(
        parse_icmpv6_message(&error6, v6_context())
            .expect("valid PTB")
            .message,
        ParsedIcmpv6Message::PacketTooBig {
            mtu: 1_280,
            quoted_packet: Ok(_),
            ..
        }
    ));
}

#[test]
fn ndp_enforces_rfc_context_and_preserves_unknown_options() {
    let source = Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0xff, 0xfe, 0, 0, 1,
    ]);
    let all_nodes = Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let context = NdpContext {
        source,
        destination: all_nodes,
        hop_limit: 255,
    };
    let options = [
        NdpOption::SourceLinkLayerAddress([2, 0, 0, 0, 0, 1]),
        NdpOption::Mtu(1_500),
        NdpOption::Unknown {
            kind: 253,
            body: &[1, 2, 3],
        },
    ];
    let advertisement = NdpPacket {
        context,
        message: NdpMessage::RouterAdvertisement {
            current_hop_limit: 64,
            managed: false,
            other_configuration: true,
            preference: 1,
            router_lifetime: 1_800,
            reachable_time: 30_000,
            retransmit_timer: 1_000,
        },
        options: &options,
    }
    .build()
    .expect("canonical RA");
    let parsed = parse_ndp_message(&advertisement, context).expect("valid RA");
    assert!(matches!(
        parsed.message,
        ParsedNdpMessage::RouterAdvertisement { preference: 1, .. }
    ));
    assert!(
        parsed
            .options
            .iter()
            .any(|option| matches!(option, ParsedNdpOption::Unknown { kind: 253, .. }))
    );
    assert!(parsed.conformance.is_canonical());

    let bad_hop = NdpContext {
        hop_limit: 64,
        ..context
    };
    assert!(parse_ndp_message(&advertisement, bad_hop).is_err());
    let mut zero_units = advertisement;
    zero_units[17] = 0;
    rewrite_transport_checksum(&mut zero_units, context);
    assert!(parse_ndp_message(&zero_units, context).is_err());

    let unspecified = Ipv6Address::new([0; 16]);
    let target = Ipv6Address::new([
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd,
    ]);
    let solicited = Ipv6Address::new([
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0xab, 0xcd,
    ]);
    assert!(
        NdpPacket {
            context: NdpContext {
                source: unspecified,
                destination: solicited,
                hop_limit: 255,
            },
            message: NdpMessage::NeighborSolicitation { target },
            options: &[NdpOption::SourceLinkLayerAddress([2, 0, 0, 0, 0, 1])],
        }
        .build()
        .is_err()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-driven test audits all RFC 4861 message families and their shared rules"
)]
fn every_ndp_message_family_round_trips_with_message_specific_rules() {
    let link_local = Ipv6Address::new([
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0xff, 0xfe, 0, 0, 1,
    ]);
    let peer = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let target = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    let all_routers = Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let all_nodes = Ipv6Address::new([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let source_lla = [NdpOption::SourceLinkLayerAddress([2, 0, 0, 0, 0, 1])];
    let target_lla = [NdpOption::TargetLinkLayerAddress([2, 0, 0, 0, 0, 2])];
    let cases = [
        (
            NdpContext {
                source: link_local,
                destination: all_routers,
                hop_limit: 255,
            },
            NdpMessage::RouterSolicitation,
            &source_lla[..],
            133,
        ),
        (
            NdpContext {
                source: link_local,
                destination: target,
                hop_limit: 255,
            },
            NdpMessage::NeighborSolicitation { target },
            &source_lla[..],
            135,
        ),
        (
            NdpContext {
                source: target,
                destination: peer,
                hop_limit: 255,
            },
            NdpMessage::NeighborAdvertisement {
                router: false,
                solicited: true,
                override_flag: true,
                target,
            },
            &target_lla[..],
            136,
        ),
        (
            NdpContext {
                source: link_local,
                destination: peer,
                hop_limit: 255,
            },
            NdpMessage::Redirect {
                target: link_local,
                destination: target,
            },
            &target_lla[..],
            137,
        ),
    ];
    for (context, message, options, message_type) in cases {
        let encoded = NdpPacket {
            context,
            message,
            options,
        }
        .build()
        .expect("canonical NDP family");
        assert_eq!(encoded[0], message_type);
        assert_eq!(
            parse_ndp_message(&encoded, context)
                .expect("NDP parse")
                .message,
            match message {
                NdpMessage::RouterSolicitation => ParsedNdpMessage::RouterSolicitation,
                NdpMessage::NeighborSolicitation { target } =>
                    ParsedNdpMessage::NeighborSolicitation { target },
                NdpMessage::NeighborAdvertisement {
                    router,
                    solicited,
                    override_flag,
                    target,
                } => ParsedNdpMessage::NeighborAdvertisement {
                    router,
                    solicited,
                    override_flag,
                    target
                },
                NdpMessage::Redirect {
                    target,
                    destination,
                } => ParsedNdpMessage::Redirect {
                    target,
                    destination
                },
                NdpMessage::RouterAdvertisement { .. } => unreachable!("separately covered"),
            }
        );
    }

    assert!(
        NdpPacket {
            context: NdpContext {
                source: target,
                destination: all_nodes,
                hop_limit: 255,
            },
            message: NdpMessage::NeighborAdvertisement {
                router: false,
                solicited: true,
                override_flag: false,
                target,
            },
            options: &target_lla,
        }
        .build()
        .is_err(),
        "a solicited NA cannot use a multicast destination"
    );
}

#[test]
fn frozen_hmac_encoding_matches_independent_sha256_vector() {
    let identity = tcp_identity();
    let secret = SessionSecret::from_os_random([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ]);
    assert_eq!(
        secret.derive(identity).full(),
        [
            0xd1, 0x35, 0xa5, 0x4a, 0xc4, 0x7b, 0x06, 0x8f, 0xf5, 0x3d, 0x8f, 0x84, 0x13, 0x71,
            0xbd, 0xf5, 0xc8, 0x8e, 0xe6, 0xea, 0x4c, 0xaa, 0x02, 0x15, 0x49, 0x1d, 0x60, 0x6c,
            0x97, 0x4b, 0xcf, 0xee,
        ]
    );
    assert_eq!(
        ProbeIdentity::new(
            IpProtocol::new(6),
            0,
            IpAddress::V4(V4_SOURCE),
            IpAddress::V6(V6_DESTINATION),
            Port::new(1),
            Port::new(2),
            0,
            0,
            0,
        ),
        Err(CorrelationIdentityError::AddressFamilyMismatch)
    );
    assert_eq!(format!("{secret:?}"), "SessionSecret([REDACTED])");
}

#[test]
fn classifiers_reject_forgery_and_label_strength_without_policy() {
    let identity = tcp_identity();
    let token = SessionSecret::from_os_random([7; 32]).derive(identity);
    let context = TransportChecksumContext::Ipv4 {
        source: V4_DESTINATION,
        destination: V4_SOURCE,
    };
    let reply = TcpSegment {
        checksum_context: context,
        source_port: Port::new(443),
        destination_port: Port::new(40_000),
        sequence_number: 9,
        acknowledgment_number: token.tcp_acknowledgment(),
        flags: TcpFlags::SYN | TcpFlags::ACK,
        window_size: 32_000,
        urgent_pointer: 0,
        options: &[],
        payload: &[],
    }
    .build()
    .expect("reply");
    let parsed = parse_tcp_segment(&reply, context).expect("valid reply");
    let tuple = ResponseTuple {
        source: IpAddress::V4(V4_DESTINATION),
        destination: IpAddress::V4(V4_SOURCE),
        source_port: Port::new(443),
        destination_port: Port::new(40_000),
    };
    assert_eq!(
        classify_tcp_reply(identity, token, tuple, parsed)
            .expect("strong SYN-ACK")
            .strength,
        EvidenceStrength::StrongTcpSequence32
    );

    let forged = TcpSegment {
        acknowledgment_number: token.tcp_acknowledgment().wrapping_add(1),
        ..TcpSegment {
            checksum_context: context,
            source_port: Port::new(443),
            destination_port: Port::new(40_000),
            sequence_number: 9,
            acknowledgment_number: 0,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            window_size: 1,
            urgent_pointer: 0,
            options: &[],
            payload: &[],
        }
    }
    .build()
    .expect("forged wire packet");
    assert_eq!(
        classify_tcp_reply(
            identity,
            token,
            tuple,
            parse_tcp_segment(&forged, context).expect("checksum-valid forgery")
        ),
        Err(CorrelationRejection::TokenMismatch)
    );

    let echo_identity = ProbeIdentity::new(
        IpProtocol::new(1),
        1,
        IpAddress::V4(V4_SOURCE),
        IpAddress::V4(V4_DESTINATION),
        Port::new(0),
        Port::new(0),
        42,
        9,
        2,
    )
    .expect("one family");
    let echo_token = SessionSecret::from_os_random([8; 32]).derive(echo_identity);
    assert_eq!(
        classify_echo_reply(
            echo_identity,
            IpAddress::V4(V4_DESTINATION),
            IpAddress::V4(V4_SOURCE),
            42,
            9,
            &echo_token.payload_token(),
            echo_token,
        )
        .expect("strong echo")
        .strength,
        EvidenceStrength::StrongPayload128
    );
    assert_eq!(classify_arp_reply().kind, CorrelationEvidenceKind::ArpReply);
    assert_eq!(
        classify_neighbor_advertisement().strength,
        EvidenceStrength::TupleCorrelatedUnauthenticated
    );
}

#[test]
fn quoted_and_direct_udp_strength_and_reuse_grace_are_explicit() {
    let identity = udp_identity();
    let token = SessionSecret::from_os_random([9; 32]).derive(identity);
    let udp = UdpDatagram {
        checksum_context: v4_context(),
        checksum_mode: UdpChecksumMode::Compute,
        source_port: Port::new(40_001),
        destination_port: Port::new(33434),
        payload: &token.payload_token(),
    }
    .build()
    .expect("tokenized UDP");
    let packet = build_ipv4(IpProtocol::new(17), &udp);
    let full_quote = parse_quoted_ip_packet(&packet).expect("full quote");
    assert_eq!(
        classify_quoted_response(identity, full_quote, token)
            .expect("token quote")
            .strength,
        EvidenceStrength::StrongPayload128
    );
    let short_quote = parse_quoted_ip_packet(&packet[..28]).expect("minimum IPv4/UDP quote");
    assert_eq!(
        classify_quoted_response(identity, short_quote, token)
            .expect("explicit weak quote")
            .strength,
        EvidenceStrength::TruncatedQuote
    );
    let fragment = Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification: 7,
        dont_fragment: false,
        more_fragments: false,
        fragment_offset: 1,
        time_to_live: 1,
        protocol: IpProtocol::new(17),
        source: V4_SOURCE,
        destination: V4_DESTINATION,
        options: &[],
        payload: &[0; 8],
    }
    .build()
    .expect("non-first fragment");
    assert_eq!(
        classify_quoted_response(
            identity,
            parse_quoted_ip_packet(&fragment).expect("valid fragment quote"),
            token,
        ),
        Err(CorrelationRejection::FragmentedQuote)
    );
    let direct_tuple = ResponseTuple {
        source: IpAddress::V4(V4_DESTINATION),
        destination: IpAddress::V4(V4_SOURCE),
        source_port: Port::new(33434),
        destination_port: Port::new(40_001),
    };
    assert_eq!(
        classify_udp_reply(identity, direct_tuple)
            .expect("direct response")
            .strength,
        EvidenceStrength::TupleCorrelatedUnauthenticated
    );

    let mut guard = CorrelationReuseGuard::new(1, 10).expect("bounded guard");
    let lease = guard.reserve(identity, 100).expect("first reservation");
    assert_eq!(guard.reserve(identity, 100), Err(ReuseGuardError::Conflict));
    guard.complete(lease, 100).expect("grace transition");
    assert_eq!(guard.reserve(identity, 109), Err(ReuseGuardError::Conflict));
    assert!(guard.reserve(identity, 110).is_ok());
}

#[test]
fn recorded_pcap_replays_to_deterministic_normalized_evidence() {
    let pcap = decode_hex(include_str!(
        "../../../test/fixtures/protocol/phase18-udp-reply.pcap.hex"
    ));
    assert_eq!(&pcap[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    assert_eq!(
        u32::from_le_bytes(pcap[20..24].try_into().expect("link type")),
        1
    );
    let captured_length = usize::try_from(u32::from_le_bytes(
        pcap[32..36].try_into().expect("record length"),
    ))
    .expect("capture length fits");
    let frame = &pcap[40..40 + captured_length];
    let parsed = parse_network_frame(frame, ParseMode::Strict).expect("captured frame");
    let ParsedNetworkPayload::Ipv4(ip) = parsed.network else {
        panic!("expected IPv4 pcap record");
    };
    let UpperLayerState::Reachable {
        protocol, payload, ..
    } = ip.upper_layer
    else {
        panic!("expected complete transport bytes");
    };
    assert_eq!(protocol, IpProtocol::new(17));
    let udp = parse_udp_datagram(
        payload,
        TransportChecksumContext::Ipv4 {
            source: ip.source,
            destination: ip.destination,
        },
    )
    .expect("captured UDP");
    let expected = ProbeIdentity::new(
        IpProtocol::new(17),
        0,
        IpAddress::V4(ip.destination),
        IpAddress::V4(ip.source),
        udp.destination_port,
        udp.source_port,
        0,
        0,
        99,
    )
    .expect("one family");
    let evidence = classify_udp_reply(
        expected,
        ResponseTuple {
            source: IpAddress::V4(ip.source),
            destination: IpAddress::V4(ip.destination),
            source_port: udp.source_port,
            destination_port: udp.destination_port,
        },
    )
    .expect("deterministic tuple evidence");
    assert_eq!(
        evidence,
        nodenet_protocols::CorrelationEvidence {
            kind: CorrelationEvidenceKind::UdpReply,
            strength: EvidenceStrength::TupleCorrelatedUnauthenticated,
        }
    );
}

fn tcp_identity() -> ProbeIdentity {
    ProbeIdentity::new(
        IpProtocol::new(6),
        0x0102_0304,
        IpAddress::V4(V4_SOURCE),
        IpAddress::V4(V4_DESTINATION),
        Port::new(40_000),
        Port::new(443),
        0,
        0,
        0x0102_0304_0506_0708,
    )
    .expect("one family")
}

fn udp_identity() -> ProbeIdentity {
    ProbeIdentity::new(
        IpProtocol::new(17),
        1,
        IpAddress::V4(V4_SOURCE),
        IpAddress::V4(V4_DESTINATION),
        Port::new(40_001),
        Port::new(33434),
        0,
        0,
        3,
    )
    .expect("one family")
}

fn build_ipv4(protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
    Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification: 1,
        dont_fragment: true,
        more_fragments: false,
        fragment_offset: 0,
        time_to_live: 1,
        protocol,
        source: V4_SOURCE,
        destination: V4_DESTINATION,
        options: &[],
        payload,
    }
    .build()
    .expect("valid IPv4")
}

fn computed_udp_v6() -> Vec<u8> {
    UdpDatagram {
        checksum_context: v6_context(),
        checksum_mode: UdpChecksumMode::Compute,
        source_port: Port::new(1),
        destination_port: Port::new(2),
        payload: &[3, 4, 5],
    }
    .build()
    .expect("valid UDP")
}

fn rewrite_transport_checksum(message: &mut [u8], context: NdpContext) {
    message[2..4].fill(0);
    let checksum = nodenet_protocols::compute_transport_checksum(
        TransportChecksumContext::Ipv6 {
            source: context.source,
            destination: context.destination,
        },
        IpProtocol::new(58),
        message,
    )
    .expect("bounded length");
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
}

fn decode_hex(input: &str) -> Vec<u8> {
    let compact: String = input
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(str::chars)
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("ASCII fixture");
            u8::from_str_radix(text, 16).expect("hex fixture")
        })
        .collect()
}
