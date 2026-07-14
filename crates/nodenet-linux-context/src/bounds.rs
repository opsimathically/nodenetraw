//! Independently enforced Phase 19 resource ceilings.

pub const MAX_NETLINK_DATAGRAM_BYTES: usize = 1_048_576;
pub const MAX_DUMP_BYTES: usize = 64 * 1_048_576;
pub const MAX_MESSAGES_PER_DUMP: usize = 65_536;
pub const MAX_ATTRIBUTES_PER_MESSAGE: usize = 256;
pub const MAX_NESTED_ATTRIBUTE_DEPTH: usize = 8;
pub const MAX_STRING_ATTRIBUTE_BYTES: usize = 256;
pub const MAX_INTERFACES: usize = 4_096;
pub const MAX_ADDRESSES: usize = 16_384;
pub const MAX_ROUTES: usize = 65_536;
pub const MAX_RULES: usize = 65_536;
pub const MAX_NEIGHBORS: usize = 65_536;
pub const MAX_MULTIPATH_NEXT_HOPS: usize = 64;
pub const MAX_LINK_LAYER_ADDRESS_BYTES: usize = 256;
pub const MAX_UNKNOWN_ATTRIBUTE_BYTES: usize = 4_096;
pub const MAX_SNAPSHOT_UNKNOWN_BYTES: usize = 8 * 1_048_576;
pub const MAX_SNAPSHOT_ATTEMPTS: usize = 3;
pub const MAX_BUFFERED_NOTIFICATIONS: usize = 8_192;
pub const MAX_BUFFERED_NOTIFICATION_BYTES: usize = 8 * 1_048_576;
pub const MAX_ROUTE_QUERY_ATTEMPTS: usize = 3;
pub const MAX_ROUTE_QUERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
pub const MAX_PENDING_ROUTE_QUERIES: usize = 1_024;
pub const MAX_RESYNC_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
