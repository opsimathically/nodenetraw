mod support;

use std::alloc::System;

use nodenet_protocols::{
    ETHER_TYPE_IPV4, EthernetFrame, EthernetHeader, Icmpv4Message, Icmpv6Message, Icmpv6Packet,
    IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet, MacAddress, NdpContext,
    NdpMessage, NdpPacket, PacketKind, PacketPlan, PacketStart, ParseMode, Port, TcpFlags,
    TcpSegment, TransportChecksumContext, UdpChecksumMode, UdpDatagram, VlanStack, inspect_packet,
    parse_icmpv4_message, parse_icmpv6_message, parse_ndp_message, parse_network_frame,
    parse_tcp_segment, parse_udp_datagram,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one instrumented region test audits the complete protocol crate allocation contract"
)]
fn allocation_contracts_are_exact() {
    let frame = support::ethernet_ipv4_udp();
    let mut output = [0_u8; 64];
    let plan = PacketPlan::new(&frame, PacketKind::Ethernet).expect("bounded fixture");

    let parse_region = Region::new(GLOBAL);
    let result = inspect_packet(&frame, PacketStart::Ethernet, ParseMode::Strict);
    let parse_stats = parse_region.change();
    assert!(result.is_ok());
    assert_eq!(parse_stats.allocations, 0);
    assert_eq!(parse_stats.reallocations, 0);

    let write_region = Region::new(GLOBAL);
    let result = plan.write_into(&mut output);
    let write_stats = write_region.change();
    assert!(result.is_ok());
    assert_eq!(write_stats.allocations, 0);
    assert_eq!(write_stats.reallocations, 0);

    let ipv6_frame = support::ethernet_ipv6_extensions();
    let network_parse_region = Region::new(GLOBAL);
    let ipv4_result = parse_network_frame(&frame, ParseMode::Strict);
    let ipv6_result = parse_network_frame(&ipv6_frame, ParseMode::Strict);
    let network_parse_stats = network_parse_region.change();
    assert!(ipv4_result.is_ok());
    assert!(ipv6_result.is_ok());
    assert_eq!(network_parse_stats.allocations, 0);
    assert_eq!(network_parse_stats.reallocations, 0);

    let ipv4_payload = [0_u8; 8];
    let ipv4 = Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification: 1,
        dont_fragment: true,
        more_fragments: false,
        fragment_offset: 0,
        time_to_live: 64,
        protocol: IpProtocol::new(17),
        source: Ipv4Address::new([192, 0, 2, 1]),
        destination: Ipv4Address::new([198, 51, 100, 2]),
        options: &[],
        payload: &ipv4_payload,
    };
    let ipv6_payload = [0_u8; 8];
    let ipv6 = Ipv6Packet {
        traffic_class: 0,
        flow_label: 1,
        hop_limit: 64,
        source: Ipv6Address::new([0; 16]),
        destination: Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        extensions: &[],
        upper_layer_protocol: IpProtocol::new(17),
        payload: &ipv6_payload,
    };
    let mut ipv4_output = [0_u8; 28];
    let mut ipv6_output = [0_u8; 48];
    let build_region = Region::new(GLOBAL);
    assert!(ipv4.write_into(&mut ipv4_output).is_ok());
    assert!(ipv6.write_into(&mut ipv6_output).is_ok());
    let build_stats = build_region.change();
    assert_eq!(build_stats.allocations, 0);
    assert_eq!(build_stats.reallocations, 0);

    let ethernet = EthernetFrame {
        header: EthernetHeader {
            destination: MacAddress::new([2, 0, 0, 0, 0, 2]),
            source: MacAddress::new([2, 0, 0, 0, 0, 1]),
            vlan: VlanStack::None,
            ether_type: ETHER_TYPE_IPV4,
        },
        payload: &ipv4_output,
    };
    let mut ethernet_output = [0_u8; 42];
    let frame_region = Region::new(GLOBAL);
    assert!(ethernet.write_into(&mut ethernet_output).is_ok());
    let frame_stats = frame_region.change();
    assert_eq!(frame_stats.allocations, 0);
    assert_eq!(frame_stats.reallocations, 0);

    let v4_transport = TransportChecksumContext::Ipv4 {
        source: ipv4.source,
        destination: ipv4.destination,
    };
    let v6_transport = TransportChecksumContext::Ipv6 {
        source: ipv6.source,
        destination: ipv6.destination,
    };
    let tcp = TcpSegment {
        checksum_context: v4_transport,
        source_port: Port::new(40_000),
        destination_port: Port::new(443),
        sequence_number: 1,
        acknowledgment_number: 0,
        flags: TcpFlags::SYN,
        window_size: 1,
        urgent_pointer: 0,
        options: &[],
        payload: &[],
    };
    let udp = UdpDatagram {
        checksum_context: v4_transport,
        checksum_mode: UdpChecksumMode::Compute,
        source_port: Port::new(40_000),
        destination_port: Port::new(53),
        payload: &[1, 2, 3, 4],
    };
    let icmpv4 = Icmpv4Message::EchoRequest {
        identifier: 1,
        sequence: 2,
        payload: &[],
    };
    let icmpv6 = Icmpv6Packet {
        checksum_context: v6_transport,
        message: Icmpv6Message::EchoRequest {
            identifier: 1,
            sequence: 2,
            payload: &[],
        },
    };
    let ndp_context = NdpContext {
        source: Ipv6Address::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        destination: ipv6.destination,
        hop_limit: 255,
    };
    let ndp = NdpPacket {
        context: ndp_context,
        message: NdpMessage::NeighborSolicitation {
            target: ipv6.destination,
        },
        options: &[],
    };
    let mut tcp_output = [0_u8; 20];
    let mut udp_output = [0_u8; 12];
    let mut icmpv4_output = [0_u8; 8];
    let mut icmpv6_output = [0_u8; 8];
    let mut ndp_output = [0_u8; 24];
    let transport_region = Region::new(GLOBAL);
    assert!(tcp.write_into(&mut tcp_output).is_ok());
    assert!(udp.write_into(&mut udp_output).is_ok());
    assert!(icmpv4.write_into(&mut icmpv4_output).is_ok());
    assert!(icmpv6.write_into(&mut icmpv6_output).is_ok());
    assert!(ndp.write_into(&mut ndp_output).is_ok());
    assert!(parse_tcp_segment(&tcp_output, v4_transport).is_ok());
    assert!(parse_udp_datagram(&udp_output, v4_transport).is_ok());
    assert!(parse_icmpv4_message(&icmpv4_output).is_ok());
    assert!(parse_icmpv6_message(&icmpv6_output, v6_transport).is_ok());
    assert!(parse_ndp_message(&ndp_output, ndp_context).is_ok());
    let transport_stats = transport_region.change();
    assert_eq!(transport_stats.allocations, 0);
    assert_eq!(transport_stats.reallocations, 0);

    let region = Region::new(GLOBAL);
    let owned = plan.to_owned();
    let stats = region.change();
    assert_eq!(owned.as_slice(), frame);
    assert_eq!(stats.allocations, 1);
    assert_eq!(stats.reallocations, 0);
    assert_eq!(stats.bytes_allocated, frame.len());
}
