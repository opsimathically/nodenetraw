use std::{
    alloc::System,
    hint::black_box,
    time::{Duration, Instant},
};

use nodenet_protocols::{
    FrameTemplate, IpProtocol, Ipv4Address, Ipv4Packet, PacketKind, PacketPlan, PacketStart,
    ParseMode, PatchDescriptor, PatchKind, PatchValue, TemplatePatch, inspect_packet,
    parse_network_frame,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const FRAME: [u8; 46] = [
    0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0, 0x45, 0, 0, 0x20, 0x12, 0x34, 0x40, 0,
    0x40, 0x11, 0x3c, 0x62, 0xc0, 0, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02, 0x9c, 0x40, 0x82, 0x9a, 0,
    0x0c, 0, 0, 0xde, 0xad, 0xbe, 0xef,
];
const IPV6_FRAME: [u8; 78] = [
    0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x86, 0xdd, 0x62, 0xa1, 0x23, 0x45, 0, 0x18, 0,
    0x40, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x2c, 0, 0, 0, 0, 0, 0, 0, 0x11, 0, 0, 0x01, 0x12, 0x34,
    0x56, 0x78, 0x9c, 0x40, 0x82, 0x9a, 0, 0x08, 0, 0,
];

fn main() {
    const ITERATIONS: u32 = 100_000;
    let plan = PacketPlan::new(&FRAME, PacketKind::Ethernet).expect("static fixture is bounded");
    let mut output = [0_u8; FRAME.len()];
    let ipv4 = Ipv4Packet {
        dscp: 0,
        ecn: 0,
        identification: 0x1234,
        dont_fragment: true,
        more_fragments: false,
        fragment_offset: 0,
        time_to_live: 64,
        protocol: IpProtocol::new(17),
        source: Ipv4Address::new([192, 0, 2, 1]),
        destination: Ipv4Address::new([198, 51, 100, 2]),
        options: &[],
        payload: &FRAME[34..],
    };
    let mut ipv4_output = [0_u8; 32];
    let descriptor = PatchDescriptor::new(PatchKind::Token, 42, 4, FRAME.len())
        .expect("static descriptor is valid");
    let template = FrameTemplate::new(&FRAME, PacketKind::Ethernet, &[descriptor])
        .expect("static template is valid");
    let patch_bytes = [1_u8, 2, 3, 4];
    let patches = [TemplatePatch {
        descriptor_index: 0,
        value: PatchValue::Bytes(&patch_bytes),
    }];
    let mut template_output = [0_u8; FRAME.len()];

    let parse_region = Region::new(GLOBAL);
    let parse_elapsed = measure(ITERATIONS, || {
        black_box(
            inspect_packet(black_box(&FRAME), PacketStart::Ethernet, ParseMode::Strict)
                .expect("static fixture parses"),
        );
    });
    let parse_stats = parse_region.change();

    let network_parse_region = Region::new(GLOBAL);
    let network_parse_elapsed = measure(ITERATIONS, || {
        black_box(
            parse_network_frame(black_box(&FRAME), ParseMode::Strict)
                .expect("static IPv4 fixture parses"),
        );
        black_box(
            parse_network_frame(black_box(&IPV6_FRAME), ParseMode::Strict)
                .expect("static IPv6 fixture parses"),
        );
    });
    let network_parse_stats = network_parse_region.change();

    let write_region = Region::new(GLOBAL);
    let write_elapsed = measure(ITERATIONS, || {
        black_box(
            plan.write_into(black_box(&mut output))
                .expect("static output is exact"),
        );
    });
    let write_stats = write_region.change();

    let build_region = Region::new(GLOBAL);
    let build_elapsed = measure(ITERATIONS, || {
        black_box(
            ipv4.write_into(black_box(&mut ipv4_output))
                .expect("static IPv4 output is exact"),
        );
    });
    let build_stats = build_region.change();

    let template_region = Region::new(GLOBAL);
    let template_elapsed = measure(ITERATIONS, || {
        black_box(
            template
                .instantiate_into(black_box(&mut template_output), black_box(&patches))
                .expect("static template output is exact"),
        );
    });
    let template_stats = template_region.change();

    assert_eq!(parse_stats.allocations, 0, "parse baseline allocated");
    assert_eq!(
        network_parse_stats.allocations, 0,
        "Phase 17 parse baseline allocated"
    );
    assert_eq!(write_stats.allocations, 0, "caller-owned build allocated");
    assert_eq!(build_stats.allocations, 0, "IPv4 build baseline allocated");
    assert_eq!(template_stats.allocations, 0, "template baseline allocated");
    println!(
        "phase16 baseline: strict Ethernet/IPv4/UDP parse {:.1} ns/op; caller-owned copy {:.1} ns/op; allocations/op 0/0",
        nanos_per_operation(parse_elapsed, ITERATIONS),
        nanos_per_operation(write_elapsed, ITERATIONS)
    );
    println!(
        "phase17 baseline: Ethernet IPv4+IPv6 parse pair {:.1} ns/op; IPv4 build {:.1} ns/op; template patch {:.1} ns/op; allocations/op 0/0/0",
        nanos_per_operation(network_parse_elapsed, ITERATIONS),
        nanos_per_operation(build_elapsed, ITERATIONS),
        nanos_per_operation(template_elapsed, ITERATIONS)
    );
}

fn measure(mut iterations: u32, mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    while iterations > 0 {
        operation();
        iterations -= 1;
    }
    start.elapsed()
}

fn nanos_per_operation(elapsed: Duration, iterations: u32) -> f64 {
    elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(iterations)
}
