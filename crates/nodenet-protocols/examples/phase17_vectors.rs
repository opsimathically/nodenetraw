use std::fmt::Write as _;

use nodenet_protocols::{
    ArpEthernetIpv4Operation, ArpEthernetIpv4Packet, ETHER_TYPE_ARP, ETHER_TYPE_IPV4,
    ETHER_TYPE_IPV6, EthernetFrame, EthernetHeader, IpProtocol, Ipv4Address, Ipv4Packet,
    Ipv6Address, Ipv6Extension, Ipv6Packet, MacAddress, VlanStack,
};

const SOURCE_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 1]);
const DESTINATION_MAC: MacAddress = MacAddress::new([0x02, 0, 0, 0, 0, 2]);
const SOURCE_IPV4: Ipv4Address = Ipv4Address::new([192, 0, 2, 1]);
const DESTINATION_IPV4: Ipv4Address = Ipv4Address::new([198, 51, 100, 2]);
const SOURCE_IPV6: Ipv6Address =
    Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const DESTINATION_IPV6: Ipv6Address =
    Ipv6Address::new([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

fn main() {
    emit("arp", ETHER_TYPE_ARP.get(), &arp_frame());
    emit("ipv4", ETHER_TYPE_IPV4.get(), &ipv4_frame());
    emit("ipv6", ETHER_TYPE_IPV6.get(), &ipv6_frame());
}

fn arp_frame() -> Vec<u8> {
    let arp = ArpEthernetIpv4Packet {
        operation: ArpEthernetIpv4Operation::Request,
        sender_hardware_address: SOURCE_MAC,
        sender_protocol_address: SOURCE_IPV4,
        target_hardware_address: MacAddress::new([0; 6]),
        target_protocol_address: Ipv4Address::new([192, 0, 2, 2]),
    }
    .build();
    ethernet(MacAddress::new([0xff; 6]), ETHER_TYPE_ARP, &arp)
}

fn ipv4_frame() -> Vec<u8> {
    let udp = [
        0x9c, 0x40, 0x82, 0x9a, 0, 0x0c, 0, 0, 0xde, 0xad, 0xbe, 0xef,
    ];
    let packet = Ipv4Packet {
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
        payload: &udp,
    }
    .build()
    .expect("static IPv4 vector is valid");
    ethernet(DESTINATION_MAC, ETHER_TYPE_IPV4, &packet)
}

fn ipv6_frame() -> Vec<u8> {
    let options = [0_u8; 6];
    let extensions = [
        Ipv6Extension::HopByHopOptions { options: &options },
        Ipv6Extension::Fragment {
            offset_units: 0,
            more_fragments: true,
            identification: 0x1234_5678,
        },
    ];
    let udp = [0x9c, 0x40, 0x82, 0x9a, 0, 8, 0, 0];
    let packet = Ipv6Packet {
        traffic_class: 0x2a,
        flow_label: 0x12345,
        hop_limit: 64,
        source: SOURCE_IPV6,
        destination: DESTINATION_IPV6,
        extensions: &extensions,
        upper_layer_protocol: IpProtocol::new(17),
        payload: &udp,
    }
    .build()
    .expect("static IPv6 vector is valid");
    ethernet(DESTINATION_MAC, ETHER_TYPE_IPV6, &packet)
}

fn ethernet(
    destination: MacAddress,
    ether_type: nodenet_protocols::EtherType,
    payload: &[u8],
) -> Vec<u8> {
    EthernetFrame {
        header: EthernetHeader {
            destination,
            source: SOURCE_MAC,
            vlan: VlanStack::None,
            ether_type,
        },
        payload,
    }
    .build()
    .expect("static Ethernet vector is valid")
}

fn emit(name: &str, protocol: u16, bytes: &[u8]) {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    println!("{name} {protocol} {encoded}");
}
