mod support;

use nodenet_protocols::{
    BuildError, EtherType, InternetChecksum, IpAddress, IpProtocol, Ipv4Address, Ipv6Address,
    MAX_ETHERNET_FRAME_LENGTH, MAX_IP_PACKET_LENGTH, MAX_OWNED_OPTION_BYTES,
    MAX_OWNED_PAYLOAD_BYTES, MacAddress, OwnedOptions, OwnedPayload, PacketKind, PacketLength,
    PacketPlan, PacketSpan, PacketStart, ParseError, ParseMode, ParseStatus, Port, ProbePort,
    Resource, inspect_packet,
};

#[test]
fn independent_fixture_has_expected_wire_fields() {
    let frame = support::ethernet_ipv4_udp();
    assert_eq!(frame.len(), 46);
    assert_eq!(&frame[0..6], &[0x02, 0, 0, 0, 0, 0x02]);
    assert_eq!(&frame[6..12], &[0x02, 0, 0, 0, 0, 0x01]);
    assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x0800);
    assert_eq!(u16::from_be_bytes([frame[16], frame[17]]), 32);
    assert_eq!(&frame[26..30], &[192, 0, 2, 1]);
    assert_eq!(&frame[30..34], &[198, 51, 100, 2]);
    assert_eq!(u16::from_be_bytes([frame[34], frame[35]]), 40_000);
    assert_eq!(u16::from_be_bytes([frame[36], frame[37]]), 33_434);
    assert_eq!(&frame[42..], &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(internet_checksum(&frame[14..34]), 0);
    assert_eq!(
        inspect_packet(&frame, PacketStart::Ethernet, ParseMode::Strict),
        Ok(ParseStatus::Complete)
    );
}

#[test]
fn strict_and_compatible_modes_are_distinct() {
    let frame = support::ethernet_ipv4_udp();
    let ip = &frame[14..];
    for length in 0..ip.len() {
        assert!(
            inspect_packet(&ip[..length], PacketStart::Ip, ParseMode::Strict).is_err(),
            "strict parser accepted truncation at {length}"
        );
        if length >= 20 {
            assert!(
                matches!(
                    inspect_packet(
                        &ip[..length],
                        PacketStart::Ip,
                        ParseMode::CompatibleIcmpQuote
                    ),
                    Ok(ParseStatus::IncompleteQuote { .. })
                ),
                "compatible parser misclassified truncation at {length}"
            );
        }
    }
    assert_eq!(
        inspect_packet(ip, PacketStart::Ip, ParseMode::CompatibleIcmpQuote),
        Ok(ParseStatus::Complete)
    );
}

#[test]
fn checked_types_preserve_wire_values_and_ranges() {
    assert_eq!(
        MacAddress::new([1, 2, 3, 4, 5, 6]).octets(),
        [1, 2, 3, 4, 5, 6]
    );
    let ipv4 = Ipv4Address::new([192, 0, 2, 1]);
    let ipv6 = Ipv6Address::new([0; 16]);
    assert_eq!(IpAddress::V4(ipv4), IpAddress::V4(ipv4));
    assert_eq!(ipv6.octets(), [0; 16]);
    assert_eq!(EtherType::new(0x88b5).get(), 0x88b5);
    assert_eq!(IpProtocol::new(253).get(), 253);
    assert_eq!(Port::new(0).get(), 0);
    assert!(ProbePort::new(0).is_err());
    assert_eq!(ProbePort::new(65_535).expect("non-zero").get(), 65_535);
    assert_eq!(InternetChecksum::new(0xabcd).to_be_bytes(), [0xab, 0xcd]);

    let input = [10, 20, 30, 40];
    let span = PacketSpan::new(1, 2, input.len()).expect("in bounds");
    assert_eq!(span.get(&input), Some(&input[1..3]));
    assert!(PacketSpan::new(usize::MAX, 2, input.len()).is_err());
    assert!(PacketSpan::new(3, 2, input.len()).is_err());
}

#[test]
fn length_and_owned_copy_limits_are_checked_before_allocation() {
    assert!(PacketLength::new(MAX_IP_PACKET_LENGTH, PacketKind::Ip).is_ok());
    assert!(PacketLength::new(MAX_IP_PACKET_LENGTH + 1, PacketKind::Ip).is_err());
    assert!(PacketLength::new(MAX_ETHERNET_FRAME_LENGTH, PacketKind::Ethernet).is_ok());
    assert!(PacketLength::new(MAX_ETHERNET_FRAME_LENGTH + 1, PacketKind::Ethernet).is_err());

    assert!(OwnedPayload::copy_from(&vec![0; MAX_OWNED_PAYLOAD_BYTES]).is_ok());
    assert!(OwnedPayload::copy_from(&vec![0; MAX_OWNED_PAYLOAD_BYTES + 1]).is_err());
    assert!(OwnedOptions::copy_from(&vec![0; MAX_OWNED_OPTION_BYTES]).is_ok());
    assert!(OwnedOptions::copy_from(&vec![0; MAX_OWNED_OPTION_BYTES + 1]).is_err());
}

#[test]
fn packet_plan_reports_length_and_is_transactional_on_error() {
    let frame = support::ethernet_ipv4_udp();
    let plan = PacketPlan::new(&frame, PacketKind::Ethernet).expect("bounded fixture");
    assert_eq!(plan.required_length().get(), frame.len());

    let mut exact = vec![0; frame.len()];
    assert_eq!(plan.write_into(&mut exact).expect("exact output"), frame);
    assert_eq!(
        inspect_packet(&exact, PacketStart::Ethernet, ParseMode::Strict),
        Ok(ParseStatus::Complete)
    );
    assert_eq!(plan.to_owned().into_vec(), frame);

    let mut short = vec![0xa5; frame.len() - 1];
    let before = short.clone();
    assert_eq!(
        plan.write_into(&mut short),
        Err(BuildError::BufferTooSmall {
            required: frame.len(),
            actual: frame.len() - 1
        })
    );
    assert_eq!(short, before);
}

#[test]
fn deterministic_arbitrary_bytes_and_mutations_never_panic() {
    let fixture = support::ethernet_ipv4_udp();
    for index in 0..fixture.len() {
        let mut mutation = fixture.clone();
        mutation[index] ^= 0xff;
        let _ = inspect_packet(&mutation, PacketStart::Ethernet, ParseMode::Strict);
    }

    let mut state = 0x4d59_5df4_d0f3_3173_u64;
    for length in 0..=2_048 {
        let mut input = vec![0; length];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state.to_le_bytes()[0];
        }
        let _ = inspect_packet(&input, PacketStart::Ethernet, ParseMode::Strict);
        let _ = inspect_packet(&input, PacketStart::Ip, ParseMode::Strict);
        let _ = inspect_packet(&input, PacketStart::Ip, ParseMode::CompatibleIcmpQuote);
    }
}

#[test]
fn structural_preflight_enforces_vlan_and_ipv6_extension_ceilings() {
    let mut triple_vlan = vec![0_u8; 14 + 3 * 4 + 20];
    triple_vlan[12..14].copy_from_slice(&0x8100_u16.to_be_bytes());
    triple_vlan[16..18].copy_from_slice(&0x8100_u16.to_be_bytes());
    triple_vlan[20..22].copy_from_slice(&0x8100_u16.to_be_bytes());
    triple_vlan[24..26].copy_from_slice(&0x0800_u16.to_be_bytes());
    assert!(matches!(
        inspect_packet(&triple_vlan, PacketStart::Ethernet, ParseMode::Strict),
        Err(ParseError::LimitExceeded {
            resource: Resource::VlanHeaders,
            actual: 3,
            maximum: 2
        })
    ));

    let nine_extensions = ipv6_extensions(&[0, 0, 0, 0, 0, 0, 0, 0, 59], 0);
    assert!(matches!(
        inspect_packet(&nine_extensions, PacketStart::Ip, ParseMode::Strict),
        Err(ParseError::LimitExceeded {
            resource: Resource::Ipv6ExtensionHeaders,
            actual: 9,
            maximum: 8
        })
    ));

    let oversized_extensions = ipv6_extensions(&[60, 59], 255);
    assert!(matches!(
        inspect_packet(&oversized_extensions, PacketStart::Ip, ParseMode::Strict),
        Err(ParseError::LimitExceeded {
            resource: Resource::Ipv6ExtensionBytes,
            actual: 4_096,
            maximum: 2_048
        })
    ));

    let mut jumbogram = vec![0_u8; 48];
    jumbogram[0] = 0x60;
    jumbogram[6] = 0;
    assert!(matches!(
        inspect_packet(&jumbogram, PacketStart::Ip, ParseMode::Strict),
        Err(ParseError::Unsupported {
            layer: nodenet_protocols::Layer::Ipv6,
            field: nodenet_protocols::Field::PacketLength
        })
    ));
}

fn ipv6_extensions(next_headers: &[u8], length_field: u8) -> Vec<u8> {
    let extension_length = (usize::from(length_field) + 1) * 8;
    let payload_length = next_headers.len() * extension_length;
    let mut packet = vec![0_u8; 40 + payload_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(
        &u16::try_from(payload_length)
            .expect("test payload fits")
            .to_be_bytes(),
    );
    packet[6] = 60;
    for (index, next_header) in next_headers.iter().copied().enumerate() {
        let offset = 40 + index * extension_length;
        packet[offset] = next_header;
        packet[offset + 1] = length_field;
    }
    packet
}

fn internet_checksum(input: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in input.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    !u16::try_from(sum).expect("folded checksum fits in 16 bits")
}
