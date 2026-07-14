//! Independently enforced portable scheduler ceilings.

use std::time::Duration;

pub const MAX_TARGET_INCLUDE_INTERVALS: usize = 65_536;
pub const MAX_TARGET_EXCLUDE_INTERVALS: usize = 65_536;
pub const MAX_NORMALIZED_TARGET_INTERVALS: usize = 65_536;
pub const MAX_PORTS_PER_PROBE_FAMILY: usize = 65_536;
pub const MAX_PROBE_DEFINITIONS: usize = 6;
pub const MAX_TRANSMIT_RATE_PER_SECOND: u32 = 1_000_000;
pub const MAX_OUTSTANDING_PROBES: usize = 262_144;
pub const MAX_RETRANSMISSIONS: u8 = 10;
pub const MAX_PROBE_TIMEOUT: Duration = Duration::from_mins(1);
pub const MAX_SESSION_DURATION: Duration = Duration::from_hours(720);
pub const MAX_LATE_GRACE_ENTRIES: usize = 262_144;
pub const MAX_TRANSITIONS_PER_DRIVE: usize = 4_096;
pub const MAX_DEFERRED_CANDIDATES: usize = 262_144;
