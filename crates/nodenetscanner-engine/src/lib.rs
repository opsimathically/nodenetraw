//! Syscall-free deterministic scan planning, scheduling, and classification.
//!
//! All time, entropy, route context, packet emission, and result storage enter
//! through injected traits. The crate performs no I/O and contains no unsafe
//! code, allowing exhaustive virtual-clock tests before Phase 22 adds Linux
//! descriptors and N-API.

#![forbid(unsafe_code)]

mod bounds;
mod error;
mod permutation;
mod plan;
mod scheduler;
mod target;
mod timing;
mod traits;
mod types;

pub use bounds::*;
pub use error::*;
pub use permutation::SeededPermutation;
pub use plan::{ProbeDefinition, ScanPlan};
pub use scheduler::ScanScheduler;
pub use target::{TargetCidr, TargetEndpoint, TargetInput, TargetIntervalInput, TargetSet};
pub use timing::{RttEstimator, TokenBucket};
pub use traits::{Clock, ContextResolver, EntropySource, ProbeTransport, ResultSink};
pub use types::*;
