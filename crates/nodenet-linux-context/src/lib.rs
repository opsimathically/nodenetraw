//! Bounded, read-only Linux route-netlink snapshots for scanner planning.
//!
//! This internal crate owns one `NETLINK_ROUTE` descriptor, issues only GET dump
//! requests, validates every multipart response, and publishes a snapshot only
//! after all link, address, route, rule, and ARP/NDP neighbor data is coherent.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(not(target_os = "linux"))]
compile_error!("nodenet-linux-context supports Linux only");

mod bounds;
mod cancellation;
mod context;
mod decoder;
mod driver;
mod error;
mod normalize;
mod planner;
mod preflight;
mod socket_options;
mod types;

pub use bounds::*;
pub use cancellation::CancellationToken;
pub use context::RouteContext;
pub use driver::{PendingContextOperation, RouteContextDriver};
pub use error::{IncompleteReason, SnapshotError, SnapshotResource};
pub use planner::plan_route;
pub use types::*;
