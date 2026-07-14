#![no_main]

use libfuzzer_sys::fuzz_target;
use nodenet_protocols::fuzzing::parse_surface;

fuzz_target!(|data: &[u8]| parse_surface(data));
