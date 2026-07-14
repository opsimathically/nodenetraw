//! Bounded entry points used only by the separate cargo-fuzz package.

use crate::{
    ArpEthernetIpv4Operation, ArpEthernetIpv4Packet, ETHER_TYPE_IPV4, EthernetFrame,
    EthernetHeader, FrameTemplate, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Extension,
    Ipv6Packet, MAX_ETHERNET_FRAME_LENGTH, MacAddress, NdpContext, PacketKind, PacketPlan,
    PacketStart, ParseMode, PatchDescriptor, PatchKind, PatchValue, TemplatePatch,
    TransportChecksumContext, VlanStack, VlanTag, VlanTagProtocol, inspect_packet,
    parse_arp_packet, parse_ethernet_frame, parse_icmpv4_message, parse_icmpv6_message,
    parse_ipv4_packet, parse_ipv6_packet, parse_ndp_message, parse_network_frame,
    parse_quoted_ip_packet, parse_tcp_segment, parse_udp_datagram,
};

/// Exercises strict and explicitly compatible parser surfaces with arbitrary bytes.
pub fn parse_surface(data: &[u8]) {
    let start = data.first().map_or(PacketStart::Ip, |byte| {
        if byte & 1 == 0 {
            PacketStart::Ethernet
        } else {
            PacketStart::Ip
        }
    });
    let payload = data.get(1..).unwrap_or_default();
    let _ = inspect_packet(payload, start, ParseMode::Strict);
    let _ = inspect_packet(payload, PacketStart::Ip, ParseMode::CompatibleIcmpQuote);
    let _ = parse_ethernet_frame(payload);
    let _ = parse_network_frame(payload, ParseMode::Strict);
    let _ = parse_arp_packet(payload);
    let _ = parse_ipv4_packet(payload, ParseMode::Strict);
    let _ = parse_ipv4_packet(payload, ParseMode::CompatibleIcmpQuote);
    let _ = parse_ipv6_packet(payload, ParseMode::Strict);
    let _ = parse_ipv6_packet(payload, ParseMode::CompatibleIcmpQuote);
    let selector = data.first().copied().unwrap_or_default();
    let v4_context = TransportChecksumContext::Ipv4 {
        source: Ipv4Address::new([192, 0, 2, selector]),
        destination: Ipv4Address::new([198, 51, 100, selector]),
    };
    let source_v6 = Ipv6Address::new([
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, selector,
    ]);
    let destination_v6 = Ipv6Address::new([
        0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, selector,
    ]);
    let v6_context = TransportChecksumContext::Ipv6 {
        source: source_v6,
        destination: destination_v6,
    };
    let _ = parse_tcp_segment(payload, v4_context);
    let _ = parse_tcp_segment(payload, v6_context);
    let _ = parse_udp_datagram(payload, v4_context);
    let _ = parse_udp_datagram(payload, v6_context);
    let _ = parse_icmpv4_message(payload);
    let _ = parse_icmpv6_message(payload, v6_context);
    let _ = parse_ndp_message(
        payload,
        NdpContext {
            source: source_v6,
            destination: destination_v6,
            hop_limit: selector,
        },
    );
    let _ = parse_quoted_ip_packet(payload);
}

/// Exercises bounded owned and caller-owned construction with arbitrary bytes.
///
/// # Panics
///
/// Panics only when a checked writer contract is violated, which is the defect
/// this fuzz entry point is intended to detect.
#[allow(
    clippy::too_many_lines,
    reason = "one fuzz entry point composes every bounded Phase 16/17 writer"
)]
pub fn serialize_surface(data: &[u8]) {
    let kind = data.first().map_or(PacketKind::Ip, |byte| {
        if byte & 1 == 0 {
            PacketKind::Ethernet
        } else {
            PacketKind::Ip
        }
    });
    let payload = data.get(1..).unwrap_or_default();
    let Ok(plan) = PacketPlan::new(payload, kind) else {
        return;
    };

    let required = plan.required_length().get();
    let mut exact = vec![0xa5; required];
    let encoded = plan.write_into(&mut exact).expect("exact checked length");
    assert_eq!(encoded, payload);
    assert_eq!(plan.to_owned().as_slice(), payload);

    if required > 0 {
        let capacity = required - 1;
        let mut short = vec![0x5a; capacity.min(MAX_ETHERNET_FRAME_LENGTH)];
        let before = short.clone();
        assert!(plan.write_into(&mut short).is_err());
        assert_eq!(short, before);
    }

    let bounded_payload = &payload[..payload.len().min(256)];
    let selector = data.first().copied().unwrap_or_default();
    let source_mac = MacAddress::new([2, 0, 0, 0, 0, selector]);
    let destination_mac = MacAddress::new([2, 0, 0, 0, 1, selector]);
    let source_ipv4 = Ipv4Address::new([192, 0, 2, selector]);
    let destination_ipv4 = Ipv4Address::new([198, 51, 100, selector]);
    let option_storage = [1_u8; 40];
    let option_length = usize::from(selector % 11) * 4;
    let ipv4 = Ipv4Packet {
        dscp: selector & 0x3f,
        ecn: selector & 0x03,
        identification: u16::from(selector) << 8 | u16::from(selector),
        dont_fragment: true,
        more_fragments: false,
        fragment_offset: 0,
        time_to_live: selector,
        protocol: IpProtocol::new(253),
        source: source_ipv4,
        destination: destination_ipv4,
        options: &option_storage[..option_length],
        payload: bounded_payload,
    };
    let ipv4_bytes = ipv4.build().expect("bounded fuzz IPv4 build");
    assert!(parse_ipv4_packet(&ipv4_bytes, ParseMode::Strict).is_ok());
    let frame = EthernetFrame {
        header: EthernetHeader {
            destination: destination_mac,
            source: source_mac,
            vlan: VlanStack::Two([
                VlanTag::new(
                    VlanTagProtocol::ProviderBridging,
                    selector & 0x07,
                    selector & 0x08 != 0,
                    u16::from(selector),
                )
                .expect("bounded fuzz outer VLAN"),
                VlanTag::new(
                    VlanTagProtocol::Dot1Q,
                    (selector >> 1) & 0x07,
                    selector & 0x10 != 0,
                    u16::from(selector) << 4,
                )
                .expect("bounded fuzz inner VLAN"),
            ]),
            ether_type: ETHER_TYPE_IPV4,
        },
        payload: &ipv4_bytes,
    }
    .build()
    .expect("bounded fuzz Ethernet build");
    assert!(parse_network_frame(&frame, ParseMode::Strict).is_ok());
    let descriptor = PatchDescriptor::new(PatchKind::SourceIpv4, 34, 4, frame.len())
        .expect("fixed source address descriptor");
    let template = FrameTemplate::new(&frame, PacketKind::Ethernet, &[descriptor])
        .expect("bounded fuzz template");
    let replacement = Ipv4Address::new([203, 0, 113, selector]);
    let patches = [TemplatePatch {
        descriptor_index: 0,
        value: PatchValue::Ipv4(replacement),
    }];
    let mut template_output = vec![0_u8; frame.len()];
    template
        .instantiate_into(&mut template_output, &patches)
        .expect("bounded fuzz template output");
    assert_eq!(&template_output[34..38], &replacement.octets());

    let mut source_ipv6 = [0_u8; 16];
    source_ipv6[15] = selector;
    let mut destination_ipv6 = [0_u8; 16];
    destination_ipv6[0] = 0x20;
    destination_ipv6[15] = selector;
    let ipv6_options = [0_u8; 6];
    let ipv6_extensions = [
        Ipv6Extension::HopByHopOptions {
            options: &ipv6_options,
        },
        Ipv6Extension::Fragment {
            offset_units: 0,
            more_fragments: false,
            identification: u32::from(selector) * 0x0101_0101,
        },
    ];
    let ipv6 = Ipv6Packet {
        traffic_class: selector,
        flow_label: u32::from(selector) << 12,
        hop_limit: selector,
        source: Ipv6Address::new(source_ipv6),
        destination: Ipv6Address::new(destination_ipv6),
        extensions: &ipv6_extensions,
        upper_layer_protocol: IpProtocol::new(253),
        payload: bounded_payload,
    };
    let ipv6_bytes = ipv6.build().expect("bounded fuzz IPv6 build");
    assert!(parse_ipv6_packet(&ipv6_bytes, ParseMode::Strict).is_ok());

    let arp = ArpEthernetIpv4Packet {
        operation: if selector & 1 == 0 {
            ArpEthernetIpv4Operation::Request
        } else {
            ArpEthernetIpv4Operation::Reply
        },
        sender_hardware_address: source_mac,
        sender_protocol_address: source_ipv4,
        target_hardware_address: destination_mac,
        target_protocol_address: destination_ipv4,
    }
    .build();
    assert!(parse_arp_packet(&arp).is_ok());
}
