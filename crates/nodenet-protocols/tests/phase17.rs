mod support;

use nodenet_protocols::{
    ArpEthernetIpv4Operation, ArpEthernetIpv4Packet, ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
    EthernetFrame, EthernetHeader, FragmentState, FrameTemplate, IpProtocol, Ipv4Address,
    Ipv4Conformance, Ipv4Packet, Ipv6Address, Ipv6Conformance, Ipv6Extension, Ipv6Packet,
    MAX_ETHERNET_FRAME_LENGTH, MAX_IP_PACKET_LENGTH, MacAddress, PacketKind, ParseError, ParseMode,
    ParsedArpPacket, ParsedIpv6Extension, ParsedNetworkPayload, PatchDescriptor, PatchKind,
    PatchValue, Resource, TemplatePatch, UpperLayerState, VlanStack, VlanTag, VlanTagProtocol,
    compute_internet_checksum, parse_arp_packet, parse_ethernet_frame, parse_ipv4_packet,
    parse_ipv6_packet, parse_network_frame,
};

const SOURCE_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
const DESTINATION_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
const SOURCE_IPV4: Ipv4Address = Ipv4Address::new([192, 0, 2, 1]);
const DESTINATION_IPV4: Ipv4Address = Ipv4Address::new([198, 51, 100, 2]);
const SOURCE_IPV6: Ipv6Address =
    Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const DESTINATION_IPV6: Ipv6Address =
    Ipv6Address::new([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

#[test]
fn ethernet_and_vlan_round_trip_transactionally() {
    let outer =
        VlanTag::new(VlanTagProtocol::ProviderBridging, 5, true, 100).expect("valid outer tag");
    let inner = VlanTag::new(VlanTagProtocol::Dot1Q, 0, false, 200).expect("valid inner tag");
    let builder = EthernetFrame {
        header: EthernetHeader {
            destination: DESTINATION_MAC,
            source: SOURCE_MAC,
            vlan: VlanStack::Two([outer, inner]),
            ether_type: ETHER_TYPE_IPV4,
        },
        payload: &[1, 2, 3, 4],
    };
    let frame = builder.build().expect("bounded Ethernet frame");
    assert_eq!(frame.len(), 26);
    assert_eq!(&frame[12..14], &0x88a8_u16.to_be_bytes());
    assert_eq!(&frame[16..18], &0x8100_u16.to_be_bytes());
    assert_eq!(&frame[20..22], &0x0800_u16.to_be_bytes());
    let parsed = parse_ethernet_frame(&frame).expect("valid double-tagged frame");
    assert_eq!(parsed.header, builder.header);
    assert_eq!(parsed.payload, builder.payload);

    let mut short = vec![0xa5; frame.len() - 1];
    let before = short.clone();
    assert!(builder.write_into(&mut short).is_err());
    assert_eq!(short, before);
    assert!(VlanTag::new(VlanTagProtocol::Dot1Q, 8, false, 1).is_err());
    assert!(VlanTag::new(VlanTagProtocol::Dot1Q, 0, false, 4096).is_err());
}

#[test]
fn arp_matches_independent_capture_and_preserves_unknown_formats() {
    let frame = support::ethernet_arp_request();
    let parsed_frame = parse_network_frame(&frame, ParseMode::Strict).expect("captured ARP");
    let ParsedNetworkPayload::Arp(ParsedArpPacket::EthernetIpv4(arp)) = parsed_frame.network else {
        panic!("expected typed Ethernet/IPv4 ARP");
    };
    assert_eq!(parsed_frame.ethernet.header.ether_type, ETHER_TYPE_ARP);
    assert_eq!(arp.operation, ArpEthernetIpv4Operation::Request);
    assert_eq!(arp.sender_hardware_address, SOURCE_MAC);
    assert_eq!(arp.sender_protocol_address, SOURCE_IPV4);
    assert_eq!(
        arp.target_protocol_address,
        Ipv4Address::new([192, 0, 2, 2])
    );
    assert_eq!(arp.build(), parsed_frame.ethernet.payload[..28]);

    let unknown = [0, 99, 0x88, 0xb5, 1, 1, 0, 77, 1, 2, 3, 4];
    let ParsedArpPacket::Unknown(parsed) = parse_arp_packet(&unknown).expect("bounded unknown ARP")
    else {
        panic!("unknown ARP combination was guessed");
    };
    assert_eq!(parsed.hardware_type, 99);
    assert_eq!(parsed.hardware_address_length, 1);
    assert_eq!(parsed.protocol_address_length, 1);
    assert_eq!(parsed.operation, 77);
    assert_eq!(parsed.sender_hardware_address, &[1]);
    assert_eq!(parsed.target_protocol_address, &[4]);
}

#[test]
fn ipv4_matches_independent_capture_and_dependency() {
    let frame = support::ethernet_ipv4_udp();
    let ip = &frame[14..];
    let parsed = parse_ipv4_packet(ip, ParseMode::Strict).expect("captured IPv4 packet");
    assert_eq!(parsed.source, SOURCE_IPV4);
    assert_eq!(parsed.destination, DESTINATION_IPV4);
    assert_eq!(parsed.identification, 0x1234);
    assert!(parsed.dont_fragment);
    assert_eq!(parsed.fragment, FragmentState::Unfragmented);
    assert!(
        matches!(parsed.upper_layer, UpperLayerState::Reachable { protocol, .. } if protocol.get() == 17)
    );
    assert!(parsed.conformance.is_canonical());

    let rebuilt = Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification: 0x1234,
        dont_fragment: true,
        more_fragments: false,
        fragment_offset: 0,
        time_to_live: 64,
        protocol: IpProtocol::new(17),
        source: SOURCE_IPV4,
        destination: DESTINATION_IPV4,
        options: &[],
        payload: &ip[20..],
    }
    .build()
    .expect("canonical IPv4 build");
    assert_eq!(rebuilt, ip);
    assert!(etherparse::SlicedPacket::from_ethernet(&frame).is_ok());
}

#[test]
fn ipv4_options_fragments_and_compatible_suffix_are_exact() {
    let options = [1_u8; 40];
    let maximum_header = ipv4_builder(&options, &[0; 8], false, false, 0)
        .build()
        .expect("maximum options");
    let parsed = parse_ipv4_packet(&maximum_header, ParseMode::Strict).expect("maximum IHL");
    assert_eq!(parsed.options, options);

    let first = ipv4_builder(&[], &[0; 8], false, true, 0)
        .build()
        .expect("first fragment");
    assert!(matches!(
        parse_ipv4_packet(&first, ParseMode::Strict)
            .expect("first fragment")
            .fragment,
        FragmentState::First {
            more_fragments: true
        }
    ));
    let non_first = ipv4_builder(&[], &[1, 2, 3], false, false, 7)
        .build()
        .expect("last non-first fragment");
    let parsed = parse_ipv4_packet(&non_first, ParseMode::Strict).expect("non-first fragment");
    assert!(matches!(
        parsed.fragment,
        FragmentState::NonFirst {
            offset_units: 7,
            ..
        }
    ));
    assert!(matches!(
        parsed.upper_layer,
        UpperLayerState::NonFirstFragment { .. }
    ));

    assert!(ipv4_builder(&[], &[0; 7], false, true, 0).build().is_err());
    assert!(ipv4_builder(&[], &[], true, true, 0).build().is_err());
    assert!(
        ipv4_builder(&[7, 1, 0, 0], &[], false, false, 0)
            .build()
            .is_err()
    );

    let complete = ipv4_builder(&[], &[0xaa; 16], false, false, 0)
        .build()
        .expect("complete packet");
    let truncated = &complete[..complete.len() - 8];
    assert!(parse_ipv4_packet(truncated, ParseMode::Strict).is_err());
    let compatible =
        parse_ipv4_packet(truncated, ParseMode::CompatibleIcmpQuote).expect("payload suffix quote");
    assert!(!compatible.complete);
    assert_eq!(compatible.payload.len(), 8);

    let mut noncanonical = maximum_header.clone();
    noncanonical[20..24].copy_from_slice(&[0, 1, 0, 0]);
    rewrite_ipv4_checksum(&mut noncanonical);
    let parsed = parse_ipv4_packet(&noncanonical, ParseMode::Strict).expect("safe padding issue");
    assert!(
        parsed
            .conformance
            .contains(Ipv4Conformance::NONZERO_OPTION_PADDING)
    );
}

#[test]
fn ipv4_malformed_lengths_and_checksum_fail_structurally() {
    let valid = ipv4_builder(&[], &[1, 2, 3, 4], false, false, 0)
        .build()
        .expect("valid IPv4");
    for mutation in [(0, 0x44), (0, 0x65), (2, 1), (3, 10), (10, 0xff)] {
        let mut malformed = valid.clone();
        malformed[mutation.0] = mutation.1;
        assert!(parse_ipv4_packet(&malformed, ParseMode::Strict).is_err());
    }
}

#[test]
fn ipv6_matches_independent_extension_capture_and_dependency() {
    let frame = support::ethernet_ipv6_extensions();
    let ip = &frame[14..];
    let parsed = parse_ipv6_packet(ip, ParseMode::Strict).expect("captured IPv6 extensions");
    assert_eq!(parsed.traffic_class, 0x2a);
    assert_eq!(parsed.flow_label, 0x12345);
    assert_eq!(parsed.extensions.len(), 2);
    assert!(matches!(
        parsed.extensions.get(0),
        Some(ParsedIpv6Extension::HopByHopOptions { .. })
    ));
    assert!(matches!(
        parsed.fragment,
        FragmentState::First {
            more_fragments: true
        }
    ));
    assert!(
        matches!(parsed.upper_layer, UpperLayerState::Reachable { protocol, .. } if protocol.get() == 17)
    );

    let options = [0_u8; 6];
    let extensions = [
        Ipv6Extension::HopByHopOptions { options: &options },
        Ipv6Extension::Fragment {
            offset_units: 0,
            more_fragments: true,
            identification: 0x1234_5678,
        },
    ];
    let rebuilt = ipv6_builder(&extensions, IpProtocol::new(17), &ip[56..])
        .build()
        .expect("canonical IPv6 build");
    assert_eq!(rebuilt, ip);
    assert!(etherparse::SlicedPacket::from_ethernet(&frame).is_ok());
}

#[test]
fn ipv6_terminals_fragments_and_order_are_explicit() {
    let unknown = ipv6_builder(&[], IpProtocol::new(253), &[1, 2, 3])
        .build()
        .expect("unknown next header");
    assert!(matches!(
        parse_ipv6_packet(&unknown, ParseMode::Strict)
            .expect("unknown terminal")
            .upper_layer,
        UpperLayerState::Unknown { protocol, .. } if protocol.get() == 253
    ));
    let esp = ipv6_builder(&[], IpProtocol::new(50), &[1, 2, 3])
        .build()
        .expect("opaque ESP");
    assert!(matches!(
        parse_ipv6_packet(&esp, ParseMode::Strict)
            .expect("ESP terminal")
            .upper_layer,
        UpperLayerState::Esp { .. }
    ));
    let no_next = ipv6_builder(&[], IpProtocol::new(59), &[])
        .build()
        .expect("No Next Header");
    assert!(matches!(
        parse_ipv6_packet(&no_next, ParseMode::Strict)
            .expect("No Next Header")
            .upper_layer,
        UpperLayerState::NoNextHeader { trailing: [] }
    ));

    let non_first_fragment = raw_ipv6_non_first_fragment();
    let parsed = parse_ipv6_packet(&non_first_fragment, ParseMode::Strict)
        .expect("non-first fragment is structurally safe");
    assert_eq!(parsed.extensions.len(), 1);
    assert!(
        matches!(parsed.upper_layer, UpperLayerState::NonFirstFragment { protocol, .. } if protocol.get() == 60)
    );

    let noncanonical = raw_ipv6_routing_then_hop_by_hop();
    let parsed = parse_ipv6_packet(&noncanonical, ParseMode::Strict)
        .expect("safe noncanonical order is reported");
    assert!(
        parsed
            .conformance
            .contains(Ipv6Conformance::HOP_BY_HOP_NOT_FIRST)
    );
    assert!(
        parsed
            .conformance
            .contains(Ipv6Conformance::NON_CANONICAL_ORDER)
    );
}

#[test]
fn ipv6_extension_bounds_and_truncation_are_hard() {
    let eight = raw_ipv6_destination_chain(8, 0);
    let parsed = parse_ipv6_packet(&eight, ParseMode::Strict).expect("eight bounded extensions");
    assert_eq!(parsed.extensions.len(), 8);
    assert!(
        parsed
            .conformance
            .contains(Ipv6Conformance::TOO_MANY_DESTINATION_OPTIONS)
    );
    let nine = raw_ipv6_destination_chain(9, 0);
    assert!(matches!(
        parse_ipv6_packet(&nine, ParseMode::Strict),
        Err(ParseError::LimitExceeded {
            resource: Resource::Ipv6ExtensionHeaders,
            ..
        })
    ));
    let oversized = raw_ipv6_destination_chain(2, 255);
    assert!(matches!(
        parse_ipv6_packet(&oversized, ParseMode::Strict),
        Err(ParseError::LimitExceeded {
            resource: Resource::Ipv6ExtensionBytes,
            ..
        })
    ));
    let exact_extension_ceiling = raw_ipv6_destination_chain(1, 255);
    let parsed = parse_ipv6_packet(&exact_extension_ceiling, ParseMode::Strict)
        .expect("one maximum-length extension");
    assert_eq!(parsed.extension_bytes, 2_048);

    let mut truncated = vec![0_u8; 42];
    write_ipv6_base(&mut truncated[..40], 8, 60);
    truncated[40] = 17;
    truncated[41] = 0;
    assert!(parse_ipv6_packet(&truncated, ParseMode::CompatibleIcmpQuote).is_err());

    let mut jumbo = vec![0_u8; 48];
    write_ipv6_base(&mut jumbo[..40], 0, 0);
    assert!(matches!(
        parse_ipv6_packet(&jumbo, ParseMode::Strict),
        Err(ParseError::Unsupported { .. })
    ));
}

#[test]
fn ipv6_extension_forms_and_canonical_order_boundaries_are_explicit() {
    let options = [0_u8; 6];
    let routing_data = [0_u8; 4];
    let extensions = [
        Ipv6Extension::HopByHopOptions { options: &options },
        Ipv6Extension::DestinationOptions { options: &options },
        Ipv6Extension::Routing {
            routing_type: 0,
            segments_left: 0,
            data: &routing_data,
        },
        Ipv6Extension::Fragment {
            offset_units: 0,
            more_fragments: false,
            identification: 7,
        },
        Ipv6Extension::Authentication {
            security_parameters_index: 8,
            sequence_number: 9,
            authentication_data: &[],
        },
        Ipv6Extension::DestinationOptions { options: &options },
    ];
    let packet = ipv6_builder(&extensions, IpProtocol::new(253), &[])
        .build()
        .expect("all supported extension forms in canonical order");
    let parsed = parse_ipv6_packet(&packet, ParseMode::Strict).expect("canonical extension chain");
    assert_eq!(parsed.extensions.len(), extensions.len());
    assert!(parsed.conformance.is_canonical());

    let final_destination_without_routing = [
        Ipv6Extension::Authentication {
            security_parameters_index: 1,
            sequence_number: 2,
            authentication_data: &[],
        },
        Ipv6Extension::DestinationOptions { options: &options },
    ];
    assert!(
        ipv6_builder(
            &final_destination_without_routing,
            IpProtocol::new(253),
            &[]
        )
        .build()
        .is_ok()
    );

    let misplaced_destination = [
        Ipv6Extension::DestinationOptions { options: &options },
        Ipv6Extension::Fragment {
            offset_units: 0,
            more_fragments: false,
            identification: 1,
        },
    ];
    assert!(
        ipv6_builder(&misplaced_destination, IpProtocol::new(253), &[])
            .build()
            .is_err()
    );

    let maximum_authentication_data = vec![0_u8; 1_016];
    let maximum_authentication = [Ipv6Extension::Authentication {
        security_parameters_index: 1,
        sequence_number: 2,
        authentication_data: &maximum_authentication_data,
    }];
    let packet = ipv6_builder(&maximum_authentication, IpProtocol::new(253), &[])
        .build()
        .expect("maximum AH length field");
    let parsed = parse_ipv6_packet(&packet, ParseMode::Strict).expect("maximum AH parse");
    assert_eq!(parsed.extension_bytes, 1_028);
}

#[test]
fn packet_size_and_transactional_writer_boundaries_are_exact() {
    let arp = ArpEthernetIpv4Packet {
        operation: ArpEthernetIpv4Operation::Reply,
        sender_hardware_address: SOURCE_MAC,
        sender_protocol_address: SOURCE_IPV4,
        target_hardware_address: DESTINATION_MAC,
        target_protocol_address: DESTINATION_IPV4,
    };
    let mut arp_short = [0xa5; 27];
    let arp_before = arp_short;
    assert!(arp.write_into(&mut arp_short).is_err());
    assert_eq!(arp_short, arp_before);

    let ipv4_payload = vec![0_u8; 65_515];
    let maximum_ipv4 = ipv4_builder(&[], &ipv4_payload, false, false, 0)
        .build()
        .expect("maximum IPv4 total length");
    assert_eq!(maximum_ipv4.len(), u16::MAX.into());
    assert!(parse_ipv4_packet(&maximum_ipv4, ParseMode::Strict).is_ok());
    let excessive_ipv4_payload = vec![0_u8; 65_516];
    assert!(
        ipv4_builder(&[], &excessive_ipv4_payload, false, false, 0)
            .build()
            .is_err()
    );

    let ipv6_payload = vec![0_u8; usize::from(u16::MAX)];
    let maximum_ipv6 = ipv6_builder(&[], IpProtocol::new(253), &ipv6_payload)
        .build()
        .expect("maximum non-jumbogram IPv6 packet");
    assert_eq!(maximum_ipv6.len(), MAX_IP_PACKET_LENGTH);
    assert!(parse_ipv6_packet(&maximum_ipv6, ParseMode::Strict).is_ok());
    let excessive_ipv6_payload = vec![0_u8; usize::from(u16::MAX) + 1];
    assert!(
        ipv6_builder(&[], IpProtocol::new(253), &excessive_ipv6_payload)
            .build()
            .is_err()
    );

    let outer = VlanTag::new(VlanTagProtocol::ProviderBridging, 0, false, 1).expect("outer");
    let inner = VlanTag::new(VlanTagProtocol::Dot1Q, 0, false, 2).expect("inner");
    let maximum_frame = EthernetFrame {
        header: EthernetHeader {
            destination: DESTINATION_MAC,
            source: SOURCE_MAC,
            vlan: VlanStack::Two([outer, inner]),
            ether_type: nodenet_protocols::ETHER_TYPE_IPV6,
        },
        payload: &maximum_ipv6,
    }
    .build()
    .expect("maximum two-tag Ethernet frame");
    assert_eq!(maximum_frame.len(), MAX_ETHERNET_FRAME_LENGTH);
    assert!(parse_network_frame(&maximum_frame, ParseMode::Strict).is_ok());

    let small_ipv4 = ipv4_builder(&[], &[0; 8], false, false, 0);
    let mut ipv4_short = [0xa5; 27];
    let ipv4_before = ipv4_short;
    assert!(small_ipv4.write_into(&mut ipv4_short).is_err());
    assert_eq!(ipv4_short, ipv4_before);
    let small_ipv6 = ipv6_builder(&[], IpProtocol::new(17), &[0; 8]);
    let mut ipv6_short = [0xa5; 47];
    let ipv6_before = ipv6_short;
    assert!(small_ipv6.write_into(&mut ipv6_short).is_err());
    assert_eq!(ipv6_short, ipv6_before);
}

#[test]
fn network_envelope_preserves_unknown_ethertype() {
    let frame = EthernetFrame {
        header: EthernetHeader {
            destination: DESTINATION_MAC,
            source: SOURCE_MAC,
            vlan: VlanStack::None,
            ether_type: nodenet_protocols::EtherType::new(0x88b5),
        },
        payload: &[9, 8, 7],
    }
    .build()
    .expect("opaque frame");
    assert!(matches!(
        parse_network_frame(&frame, ParseMode::Strict)
            .expect("opaque EtherType")
            .network,
        ParsedNetworkPayload::Opaque { ether_type, payload }
            if ether_type.get() == 0x88b5 && payload == [9, 8, 7]
    ));
}

#[test]
fn frame_template_patching_matches_a_full_rebuild() {
    let old_token = [0x11_u8; 16];
    let new_token = [0x22_u8; 16];
    let initial = ethernet_ipv4_token_frame(
        SOURCE_MAC,
        DESTINATION_MAC,
        SOURCE_IPV4,
        DESTINATION_IPV4,
        0x1111,
        &old_token,
    );
    let new_source_mac = MacAddress::new([2, 0, 0, 0, 0, 9]);
    let new_destination_mac = MacAddress::new([2, 0, 0, 0, 0, 10]);
    let new_source = Ipv4Address::new([203, 0, 113, 1]);
    let new_destination = Ipv4Address::new([203, 0, 113, 2]);
    let expected = ethernet_ipv4_token_frame(
        new_source_mac,
        new_destination_mac,
        new_source,
        new_destination,
        0x2222,
        &new_token,
    );
    let descriptors = [
        PatchDescriptor::new(PatchKind::DestinationMac, 0, 6, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::SourceMac, 6, 6, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::Ipv4TotalLength, 16, 2, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::Ipv4Identification, 18, 2, initial.len())
            .expect("descriptor"),
        PatchDescriptor::new(PatchKind::Ipv4HeaderChecksum, 24, 2, initial.len())
            .expect("descriptor"),
        PatchDescriptor::new(PatchKind::SourceIpv4, 26, 4, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::DestinationIpv4, 30, 4, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::Token, 34, 16, initial.len()).expect("descriptor"),
    ];
    let template = FrameTemplate::new(&initial, PacketKind::Ethernet, &descriptors)
        .expect("valid frame template");
    let checksum = u16::from_be_bytes([expected[24], expected[25]]);
    let total_length = u16::from_be_bytes([expected[16], expected[17]]);
    let patches = [
        TemplatePatch {
            descriptor_index: 0,
            value: PatchValue::Mac(new_destination_mac),
        },
        TemplatePatch {
            descriptor_index: 1,
            value: PatchValue::Mac(new_source_mac),
        },
        TemplatePatch {
            descriptor_index: 2,
            value: PatchValue::U16(total_length),
        },
        TemplatePatch {
            descriptor_index: 3,
            value: PatchValue::U16(0x2222),
        },
        TemplatePatch {
            descriptor_index: 4,
            value: PatchValue::U16(checksum),
        },
        TemplatePatch {
            descriptor_index: 5,
            value: PatchValue::Ipv4(new_source),
        },
        TemplatePatch {
            descriptor_index: 6,
            value: PatchValue::Ipv4(new_destination),
        },
        TemplatePatch {
            descriptor_index: 7,
            value: PatchValue::Bytes(&new_token),
        },
    ];
    assert_eq!(
        template.instantiate(&patches).expect("patched frame"),
        expected
    );

    let mut output = vec![0xa5; initial.len()];
    let before = output.clone();
    let mut short = vec![0xa5; initial.len() - 1];
    let short_before = short.clone();
    assert!(template.instantiate_into(&mut short, &patches).is_err());
    assert_eq!(short, short_before);
    let invalid = [patches[0], patches[0]];
    assert!(template.instantiate_into(&mut output, &invalid).is_err());
    assert_eq!(output, before);
    let overlap = [
        PatchDescriptor::new(PatchKind::SourceIpv4, 26, 4, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::Token, 28, 4, initial.len()).expect("descriptor"),
    ];
    assert!(FrameTemplate::new(&initial, PacketKind::Ethernet, &overlap).is_err());
}

#[test]
fn ipv6_template_patching_matches_a_full_rebuild() {
    let old_token = [0x11_u8; 16];
    let new_token = [0x22_u8; 16];
    let initial = ipv6_fragment_token_packet(SOURCE_IPV6, DESTINATION_IPV6, 1, &old_token);
    let new_source = Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let new_destination =
        Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let expected = ipv6_fragment_token_packet(new_source, new_destination, 2, &new_token);
    let descriptors = [
        PatchDescriptor::new(PatchKind::Ipv6PayloadLength, 4, 2, initial.len())
            .expect("descriptor"),
        PatchDescriptor::new(PatchKind::SourceIpv6, 8, 16, initial.len()).expect("descriptor"),
        PatchDescriptor::new(PatchKind::DestinationIpv6, 24, 16, initial.len())
            .expect("descriptor"),
        PatchDescriptor::new(PatchKind::Ipv6FragmentIdentification, 44, 4, initial.len())
            .expect("descriptor"),
        PatchDescriptor::new(PatchKind::Token, 48, 16, initial.len()).expect("descriptor"),
    ];
    let template =
        FrameTemplate::new(&initial, PacketKind::Ip, &descriptors).expect("IPv6 template");
    let patches = [
        TemplatePatch {
            descriptor_index: 0,
            value: PatchValue::U16(24),
        },
        TemplatePatch {
            descriptor_index: 1,
            value: PatchValue::Ipv6(new_source),
        },
        TemplatePatch {
            descriptor_index: 2,
            value: PatchValue::Ipv6(new_destination),
        },
        TemplatePatch {
            descriptor_index: 3,
            value: PatchValue::U32(2),
        },
        TemplatePatch {
            descriptor_index: 4,
            value: PatchValue::Bytes(&new_token),
        },
    ];
    assert_eq!(
        template.instantiate(&patches).expect("patched IPv6"),
        expected
    );
}

fn ipv4_builder<'a>(
    options: &'a [u8],
    payload: &'a [u8],
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u16,
) -> Ipv4Packet<'a> {
    Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification: 0x1234,
        dont_fragment,
        more_fragments,
        fragment_offset,
        time_to_live: 64,
        protocol: IpProtocol::new(17),
        source: SOURCE_IPV4,
        destination: DESTINATION_IPV4,
        options,
        payload,
    }
}

fn ipv6_builder<'a>(
    extensions: &'a [Ipv6Extension<'a>],
    upper_layer_protocol: IpProtocol,
    payload: &'a [u8],
) -> Ipv6Packet<'a> {
    Ipv6Packet {
        traffic_class: 0x2a,
        flow_label: 0x12345,
        hop_limit: 64,
        source: SOURCE_IPV6,
        destination: DESTINATION_IPV6,
        extensions,
        upper_layer_protocol,
        payload,
    }
}

fn rewrite_ipv4_checksum(packet: &mut [u8]) {
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    packet[10..12].fill(0);
    let checksum = compute_internet_checksum(&packet[..header_length]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn raw_ipv6_non_first_fragment() -> Vec<u8> {
    let mut packet = vec![0_u8; 56];
    write_ipv6_base(&mut packet[..40], 16, 44);
    packet[40] = 60;
    packet[42..44].copy_from_slice(&(1_u16 << 3).to_be_bytes());
    packet[44..48].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
    packet[48] = 17;
    packet[49] = 0;
    packet
}

fn raw_ipv6_routing_then_hop_by_hop() -> Vec<u8> {
    let mut packet = vec![0_u8; 56];
    write_ipv6_base(&mut packet[..40], 16, 43);
    packet[40] = 0;
    packet[41] = 0;
    packet[48] = 17;
    packet[49] = 0;
    packet
}

fn raw_ipv6_destination_chain(count: usize, length_field: u8) -> Vec<u8> {
    let extension_length = (usize::from(length_field) + 1) * 8;
    let payload_length = count * extension_length;
    let mut packet = vec![0_u8; 40 + payload_length];
    write_ipv6_base(
        &mut packet[..40],
        u16::try_from(payload_length).expect("test chain fits IPv6 payload"),
        60,
    );
    for index in 0..count {
        let offset = 40 + index * extension_length;
        packet[offset] = if index + 1 == count { 59 } else { 60 };
        packet[offset + 1] = length_field;
    }
    packet
}

fn write_ipv6_base(header: &mut [u8], payload_length: u16, next_header: u8) {
    header[0] = 0x60;
    header[4..6].copy_from_slice(&payload_length.to_be_bytes());
    header[6] = next_header;
    header[7] = 64;
    header[8..24].copy_from_slice(&SOURCE_IPV6.octets());
    header[24..40].copy_from_slice(&DESTINATION_IPV6.octets());
}

fn ethernet_ipv4_token_frame(
    source_mac: MacAddress,
    destination_mac: MacAddress,
    source: Ipv4Address,
    destination: Ipv4Address,
    identification: u16,
    token: &[u8],
) -> Vec<u8> {
    let ip = Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification,
        dont_fragment: true,
        more_fragments: false,
        fragment_offset: 0,
        time_to_live: 64,
        protocol: IpProtocol::new(253),
        source,
        destination,
        options: &[],
        payload: token,
    }
    .build()
    .expect("template IPv4 packet");
    EthernetFrame {
        header: EthernetHeader {
            destination: destination_mac,
            source: source_mac,
            vlan: VlanStack::None,
            ether_type: ETHER_TYPE_IPV4,
        },
        payload: &ip,
    }
    .build()
    .expect("template Ethernet frame")
}

fn ipv6_fragment_token_packet(
    source: Ipv6Address,
    destination: Ipv6Address,
    identification: u32,
    token: &[u8; 16],
) -> Vec<u8> {
    let extensions = [Ipv6Extension::Fragment {
        offset_units: 0,
        more_fragments: false,
        identification,
    }];
    Ipv6Packet {
        traffic_class: 0,
        flow_label: 0,
        hop_limit: 64,
        source,
        destination,
        extensions: &extensions,
        upper_layer_protocol: IpProtocol::new(253),
        payload: token,
    }
    .build()
    .expect("bounded IPv6 token packet")
}
