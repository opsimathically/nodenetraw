#![allow(
    dead_code,
    reason = "each integration-test binary uses a different shared fixture subset"
)]

pub const ETHERNET_IPV4_UDP_HEX: &str =
    include_str!("../../../../test/fixtures/protocol/ethernet-ipv4-udp.hex");
pub const ETHERNET_ARP_REQUEST_HEX: &str =
    include_str!("../../../../test/fixtures/protocol/ethernet-arp-request.hex");
pub const ETHERNET_IPV6_EXTENSIONS_HEX: &str =
    include_str!("../../../../test/fixtures/protocol/ethernet-ipv6-extensions.hex");

pub fn decode_hex_fixture(source: &str) -> Vec<u8> {
    let compact: String = source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "fixture has an incomplete octet");
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture is ASCII");
            u8::from_str_radix(text, 16).expect("fixture contains only hexadecimal octets")
        })
        .collect()
}

pub fn ethernet_ipv4_udp() -> Vec<u8> {
    decode_hex_fixture(ETHERNET_IPV4_UDP_HEX)
}

pub fn ethernet_arp_request() -> Vec<u8> {
    decode_hex_fixture(ETHERNET_ARP_REQUEST_HEX)
}

pub fn ethernet_ipv6_extensions() -> Vec<u8> {
    decode_hex_fixture(ETHERNET_IPV6_EXTENSIONS_HEX)
}
