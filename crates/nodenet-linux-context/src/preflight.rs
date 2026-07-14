use crate::{
    IncompleteReason, MAX_ATTRIBUTES_PER_MESSAGE, MAX_MULTIPATH_NEXT_HOPS,
    MAX_NESTED_ATTRIBUTE_DEPTH, MAX_STRING_ATTRIBUTE_BYTES, SnapshotError, SnapshotResource,
};

const NETLINK_HEADER_LENGTH: usize = 16;
const NLA_HEADER_LENGTH: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(3 << 14);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DumpKind {
    Link,
    Address,
    Route,
    Rule,
    Neighbor,
}

impl DumpKind {
    pub(crate) const fn response_type(self) -> u16 {
        match self {
            Self::Link => 16,
            Self::Address => 20,
            Self::Route => 24,
            Self::Neighbor => 28,
            Self::Rule => 32,
        }
    }

    pub(crate) const fn from_notification_type(message_type: u16) -> Option<Self> {
        match message_type {
            16 | 17 => Some(Self::Link),
            20 | 21 => Some(Self::Address),
            24 | 25 => Some(Self::Route),
            28 | 29 => Some(Self::Neighbor),
            32 | 33 => Some(Self::Rule),
            _ => None,
        }
    }

    const fn fixed_header_length(self) -> usize {
        match self {
            Self::Link => 16,
            Self::Address => 8,
            Self::Route | Self::Rule | Self::Neighbor => 12,
        }
    }
}

pub(crate) fn validate_inner_message(message: &[u8], kind: DumpKind) -> Result<(), SnapshotError> {
    let attributes_offset = NETLINK_HEADER_LENGTH
        .checked_add(kind.fixed_header_length())
        .ok_or_else(|| SnapshotError::incomplete(IncompleteReason::UnexpectedMessage))?;
    let attributes = message
        .get(attributes_offset..)
        .ok_or_else(|| SnapshotError::decode("netlink fixed header", "message is truncated"))?;
    let mut count = 0_usize;
    validate_attributes(attributes, kind, 0, &mut count)
}

fn validate_attributes(
    input: &[u8],
    message_kind: DumpKind,
    depth: usize,
    count: &mut usize,
) -> Result<(), SnapshotError> {
    if depth > MAX_NESTED_ATTRIBUTE_DEPTH {
        return Err(SnapshotError::LimitExceeded {
            resource: SnapshotResource::AttributeDepth,
            actual: depth,
            maximum: MAX_NESTED_ATTRIBUTE_DEPTH,
        });
    }
    let mut offset = 0_usize;
    while offset < input.len() {
        if input.len() - offset < NLA_HEADER_LENGTH {
            return Err(SnapshotError::decode(
                "netlink attribute header",
                "trailing bytes do not contain a complete header",
            ));
        }
        let length = usize::from(u16::from_ne_bytes([input[offset], input[offset + 1]]));
        if length < NLA_HEADER_LENGTH {
            return Err(SnapshotError::decode(
                "netlink attribute length",
                "attribute length is smaller than its header",
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| SnapshotError::decode("netlink attribute length", "offset overflow"))?;
        if end > input.len() {
            return Err(SnapshotError::decode(
                "netlink attribute length",
                "attribute extends beyond its message",
            ));
        }
        *count = count.checked_add(1).ok_or(SnapshotError::LimitExceeded {
            resource: SnapshotResource::MessageAttributes,
            actual: usize::MAX,
            maximum: MAX_ATTRIBUTES_PER_MESSAGE,
        })?;
        if *count > MAX_ATTRIBUTES_PER_MESSAGE {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::MessageAttributes,
                actual: *count,
                maximum: MAX_ATTRIBUTES_PER_MESSAGE,
            });
        }
        let raw_kind = u16::from_ne_bytes([input[offset + 2], input[offset + 3]]);
        let kind = raw_kind & NLA_TYPE_MASK;
        let value = &input[offset + NLA_HEADER_LENGTH..end];
        if is_string_attribute(message_kind, kind) && value.len() > MAX_STRING_ATTRIBUTE_BYTES {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::StringBytes,
                actual: value.len(),
                maximum: MAX_STRING_ATTRIBUTE_BYTES,
            });
        }
        if message_kind == DumpKind::Route && kind == 9 {
            validate_multipath(value, depth + 1, count)?;
        } else if raw_kind & NLA_F_NESTED != 0 || (message_kind == DumpKind::Route && kind == 8) {
            validate_attributes(value, message_kind, depth + 1, count)?;
        }
        let aligned = align4(length).ok_or_else(|| {
            SnapshotError::decode("netlink attribute alignment", "length overflow")
        })?;
        offset = offset.checked_add(aligned).ok_or_else(|| {
            SnapshotError::decode("netlink attribute alignment", "offset overflow")
        })?;
        if offset > input.len() {
            return Err(SnapshotError::decode(
                "netlink attribute padding",
                "aligned attribute extends beyond its message",
            ));
        }
    }
    Ok(())
}

fn validate_multipath(input: &[u8], depth: usize, count: &mut usize) -> Result<(), SnapshotError> {
    let mut offset = 0_usize;
    let mut next_hops = 0_usize;
    while offset < input.len() {
        if input.len() - offset < 8 {
            return Err(SnapshotError::decode(
                "route multipath",
                "next-hop header is truncated",
            ));
        }
        let length = usize::from(u16::from_ne_bytes([input[offset], input[offset + 1]]));
        if length < 8 {
            return Err(SnapshotError::decode(
                "route multipath",
                "next-hop length is smaller than its header",
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| SnapshotError::decode("route multipath", "next-hop offset overflow"))?;
        if end > input.len() {
            return Err(SnapshotError::decode(
                "route multipath",
                "next hop extends beyond the multipath attribute",
            ));
        }
        next_hops += 1;
        if next_hops > MAX_MULTIPATH_NEXT_HOPS {
            return Err(SnapshotError::LimitExceeded {
                resource: SnapshotResource::MultipathNextHops,
                actual: next_hops,
                maximum: MAX_MULTIPATH_NEXT_HOPS,
            });
        }
        validate_attributes(&input[offset + 8..end], DumpKind::Route, depth, count)?;
        offset =
            offset
                .checked_add(align4(length).ok_or_else(|| {
                    SnapshotError::decode("route multipath", "alignment overflow")
                })?)
                .ok_or_else(|| SnapshotError::decode("route multipath", "offset overflow"))?;
        if offset > input.len() {
            return Err(SnapshotError::decode(
                "route multipath",
                "aligned next hop extends beyond its attribute",
            ));
        }
    }
    Ok(())
}

const fn is_string_attribute(message: DumpKind, kind: u16) -> bool {
    match message {
        DumpKind::Link => matches!(kind, 3 | 6 | 20 | 38 | 56 | 57),
        DumpKind::Address => kind == 3,
        DumpKind::Rule => matches!(kind, 3 | 17),
        DumpKind::Route | DumpKind::Neighbor => false,
    }
}

const fn align4(length: usize) -> Option<usize> {
    match length.checked_add(3) {
        Some(value) => Some(value & !3),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{DumpKind, NLA_F_NESTED, validate_inner_message};
    use crate::{SnapshotError, SnapshotResource};

    #[test]
    fn enforces_attribute_count_string_and_depth_ceilings() {
        let attributes = (0..257).flat_map(|_| attribute(1, &[])).collect::<Vec<_>>();
        assert_limit(
            &validate_inner_message(&inner(DumpKind::Link, &attributes), DumpKind::Link)
                .unwrap_err(),
            SnapshotResource::MessageAttributes,
        );

        assert_limit(
            &validate_inner_message(
                &inner(DumpKind::Link, &attribute(3, &[b'a'; 257])),
                DumpKind::Link,
            )
            .unwrap_err(),
            SnapshotResource::StringBytes,
        );

        let mut nested = attribute(1, &[]);
        for _ in 0..9 {
            nested = attribute(NLA_F_NESTED | 1, &nested);
        }
        assert_limit(
            &validate_inner_message(&inner(DumpKind::Route, &nested), DumpKind::Route).unwrap_err(),
            SnapshotResource::AttributeDepth,
        );
    }

    #[test]
    fn enforces_multipath_ceiling_and_structure() {
        let next_hops = (0..65)
            .flat_map(|_| [8_u8, 0, 0, 0, 1, 0, 0, 0])
            .collect::<Vec<_>>();
        assert_limit(
            &validate_inner_message(
                &inner(DumpKind::Route, &attribute(9, &next_hops)),
                DumpKind::Route,
            )
            .unwrap_err(),
            SnapshotResource::MultipathNextHops,
        );

        assert!(matches!(
            validate_inner_message(
                &inner(DumpKind::Route, &attribute(9, &[7, 0, 0, 0, 0, 0, 0, 0])),
                DumpKind::Route,
            ),
            Err(SnapshotError::Decode { .. })
        ));
    }

    fn inner(kind: DumpKind, attributes: &[u8]) -> Vec<u8> {
        let fixed = match kind {
            DumpKind::Link => 16,
            DumpKind::Address => 8,
            DumpKind::Route | DumpKind::Rule | DumpKind::Neighbor => 12,
        };
        let mut output = vec![0_u8; 16 + fixed];
        output.extend_from_slice(attributes);
        output
    }

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut output = vec![0_u8; (length + 3) & !3];
        output[0..2].copy_from_slice(&u16::try_from(length).unwrap().to_ne_bytes());
        output[2..4].copy_from_slice(&kind.to_ne_bytes());
        output[4..length].copy_from_slice(value);
        output
    }

    fn assert_limit(error: &SnapshotError, expected: SnapshotResource) {
        assert!(matches!(
            error,
            SnapshotError::LimitExceeded { resource, .. } if *resource == expected
        ));
    }
}
