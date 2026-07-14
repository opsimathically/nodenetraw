#![no_main]

use libfuzzer_sys::fuzz_target;
use nodenet_protocols::fuzzing::serialize_surface;

fuzz_target!(|data: &[u8]| serialize_surface(data));
