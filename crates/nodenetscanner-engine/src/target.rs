use nodenet_protocols::{IpAddress, Ipv4Address, Ipv6Address};

use crate::{
    MAX_NORMALIZED_TARGET_INTERVALS, MAX_TARGET_EXCLUDE_INTERVALS, MAX_TARGET_INCLUDE_INTERVALS,
    ScanTarget, TargetError, TargetScope,
};

/// One target endpoint and optional IPv6 interface zone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetEndpoint {
    pub address: IpAddress,
    pub scope: Option<TargetScope>,
}

impl TargetEndpoint {
    /// Validates zone use for one address.
    ///
    /// # Errors
    ///
    /// Rejects zones on IPv4/global IPv6 and missing zones on scoped IPv6.
    pub fn new(address: IpAddress, scope: Option<TargetScope>) -> Result<Self, TargetError> {
        validate_scope(address, scope)?;
        Ok(Self { address, scope })
    }
}

/// One IPv4/IPv6 CIDR target.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetCidr {
    pub network: TargetEndpoint,
    pub prefix_length: u8,
}

/// One inclusive address range.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TargetIntervalInput {
    pub start: TargetEndpoint,
    pub end: TargetEndpoint,
}

/// Accepted compact target input forms.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetInput {
    Address(TargetEndpoint),
    Cidr(TargetCidr),
    Range(TargetIntervalInput),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GroupKey {
    family: u8,
    scope: Option<TargetScope>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawInterval {
    group: GroupKey,
    start: u128,
    end: u128,
}

impl RawInterval {
    const fn count(self) -> Option<u128> {
        (self.end - self.start).checked_add(1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NormalizedInterval {
    raw: RawInterval,
    family_end: u64,
}

/// Sorted, disjoint, exclusion-applied compact target set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetSet {
    intervals: Vec<NormalizedInterval>,
    ipv4_indices: Vec<usize>,
    ipv6_indices: Vec<usize>,
    ipv4_count: u64,
    ipv6_count: u64,
}

impl TargetSet {
    /// Normalizes includes and exclusions without expanding addresses.
    ///
    /// # Errors
    ///
    /// Rejects malformed families/zones/ranges, independent interval ceilings,
    /// empty output, and address-count overflow.
    pub fn normalize(
        includes: &[TargetInput],
        excludes: &[TargetInput],
    ) -> Result<Self, TargetError> {
        if includes.is_empty() {
            return Err(TargetError::Empty);
        }
        if includes.len() > MAX_TARGET_INCLUDE_INTERVALS {
            return Err(TargetError::TooManyIncludes);
        }
        if excludes.len() > MAX_TARGET_EXCLUDE_INTERVALS {
            return Err(TargetError::TooManyExcludes);
        }
        let includes = merge_inputs(includes)?;
        let excludes = merge_inputs(excludes)?;
        let applied = subtract(&includes, &excludes)?;
        if applied.is_empty() {
            return Err(TargetError::Empty);
        }

        let mut intervals = Vec::with_capacity(applied.len());
        let mut ipv4_indices = Vec::new();
        let mut ipv6_indices = Vec::new();
        let mut ipv4_count = 0_u64;
        let mut ipv6_count = 0_u64;
        for raw in applied {
            let count = raw
                .count()
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(TargetError::TargetCountOverflow)?;
            let family_end = match raw.group.family {
                4 => {
                    ipv4_count = ipv4_count
                        .checked_add(count)
                        .ok_or(TargetError::TargetCountOverflow)?;
                    ipv4_count
                }
                6 => {
                    ipv6_count = ipv6_count
                        .checked_add(count)
                        .ok_or(TargetError::TargetCountOverflow)?;
                    ipv6_count
                }
                _ => unreachable!("target conversion creates only IPv4/IPv6 groups"),
            };
            let index = intervals.len();
            intervals.push(NormalizedInterval { raw, family_end });
            if raw.group.family == 4 {
                ipv4_indices.push(index);
            } else {
                ipv6_indices.push(index);
            }
        }
        ipv4_count
            .checked_add(ipv6_count)
            .ok_or(TargetError::TargetCountOverflow)?;
        Ok(Self {
            intervals,
            ipv4_indices,
            ipv6_indices,
            ipv4_count,
            ipv6_count,
        })
    }

    #[must_use]
    pub const fn ipv4_count(&self) -> u64 {
        self.ipv4_count
    }

    #[must_use]
    pub const fn ipv6_count(&self) -> u64 {
        self.ipv6_count
    }

    #[must_use]
    pub const fn interval_count(&self) -> usize {
        self.intervals.len()
    }

    #[must_use]
    pub fn count(&self) -> u64 {
        self.ipv4_count + self.ipv6_count
    }

    /// Lazily resolves one family-relative address index.
    #[must_use]
    pub fn target_at_family(&self, family: u8, index: u64) -> Option<ScanTarget> {
        let indices = match family {
            4 => &self.ipv4_indices,
            6 => &self.ipv6_indices,
            _ => return None,
        };
        let position =
            indices.partition_point(|interval| self.intervals[*interval].family_end <= index);
        let interval_index = *indices.get(position)?;
        let interval = self.intervals[interval_index];
        let previous_end = position
            .checked_sub(1)
            .map_or(0, |value| self.intervals[indices[value]].family_end);
        let offset = index.checked_sub(previous_end)?;
        let value = interval.raw.start.checked_add(u128::from(offset))?;
        Some(ScanTarget {
            address: numeric_address(family, value)?,
            scope: interval.raw.group.scope,
        })
    }
}

fn merge_inputs(inputs: &[TargetInput]) -> Result<Vec<RawInterval>, TargetError> {
    let mut intervals = Vec::with_capacity(inputs.len());
    for input in inputs {
        intervals.push(input_interval(*input)?);
    }
    intervals.sort_unstable_by_key(|value| (value.group, value.start, value.end));
    let mut merged: Vec<RawInterval> = Vec::with_capacity(intervals.len());
    for interval in intervals {
        if let Some(last) = merged.last_mut()
            && last.group == interval.group
            && interval.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(interval.end);
            continue;
        }
        merged.push(interval);
    }
    Ok(merged)
}

fn subtract(
    includes: &[RawInterval],
    excludes: &[RawInterval],
) -> Result<Vec<RawInterval>, TargetError> {
    let mut output = Vec::new();
    let mut exclusion_index = 0_usize;
    for include in includes {
        while exclusion_index < excludes.len()
            && (excludes[exclusion_index].group < include.group
                || (excludes[exclusion_index].group == include.group
                    && excludes[exclusion_index].end < include.start))
        {
            exclusion_index += 1;
        }
        let mut cursor = include.start;
        let mut consumed = false;
        let mut current = exclusion_index;
        while current < excludes.len() {
            let exclusion = excludes[current];
            if exclusion.group != include.group || exclusion.start > include.end {
                break;
            }
            if exclusion.start > cursor {
                push_output(
                    &mut output,
                    RawInterval {
                        group: include.group,
                        start: cursor,
                        end: exclusion.start - 1,
                    },
                )?;
            }
            if exclusion.end >= include.end {
                consumed = true;
                break;
            }
            cursor = cursor.max(exclusion.end + 1);
            current += 1;
        }
        if !consumed && cursor <= include.end {
            push_output(
                &mut output,
                RawInterval {
                    group: include.group,
                    start: cursor,
                    end: include.end,
                },
            )?;
        }
    }
    Ok(output)
}

fn push_output(output: &mut Vec<RawInterval>, value: RawInterval) -> Result<(), TargetError> {
    if output.len() == MAX_NORMALIZED_TARGET_INTERVALS {
        return Err(TargetError::TooManyNormalizedIntervals);
    }
    output.push(value);
    Ok(())
}

fn input_interval(input: TargetInput) -> Result<RawInterval, TargetError> {
    match input {
        TargetInput::Address(value) => {
            validate_scope(value.address, value.scope)?;
            let (family, numeric) = address_numeric(value.address);
            Ok(RawInterval {
                group: GroupKey {
                    family,
                    scope: value.scope,
                },
                start: numeric,
                end: numeric,
            })
        }
        TargetInput::Range(value) => range_interval(value),
        TargetInput::Cidr(value) => cidr_interval(value),
    }
}

fn range_interval(value: TargetIntervalInput) -> Result<RawInterval, TargetError> {
    let (start_family, start) = address_numeric(value.start.address);
    let (end_family, end) = address_numeric(value.end.address);
    if start_family != end_family {
        return Err(TargetError::AddressFamilyMismatch);
    }
    if value.start.scope != value.end.scope {
        return Err(TargetError::ScopeMismatch);
    }
    if start > end {
        return Err(TargetError::ReversedRange);
    }
    validate_interval_scope(start_family, start, end, value.start.scope)?;
    Ok(RawInterval {
        group: GroupKey {
            family: start_family,
            scope: value.start.scope,
        },
        start,
        end,
    })
}

fn cidr_interval(value: TargetCidr) -> Result<RawInterval, TargetError> {
    let (family, address) = address_numeric(value.network.address);
    let width = if family == 4 { 32 } else { 128 };
    if value.prefix_length > width {
        return Err(TargetError::InvalidPrefixLength);
    }
    let host_bits = width - value.prefix_length;
    let mask = if host_bits == 128 {
        0
    } else {
        u128::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0)
    };
    let family_mask = if family == 4 {
        u128::from(u32::MAX)
    } else {
        u128::MAX
    };
    let start = address & mask & family_mask;
    let end = start | ((!mask) & family_mask);
    validate_interval_scope(family, start, end, value.network.scope)?;
    Ok(RawInterval {
        group: GroupKey {
            family,
            scope: value.network.scope,
        },
        start,
        end,
    })
}

fn validate_interval_scope(
    family: u8,
    start: u128,
    end: u128,
    scope: Option<TargetScope>,
) -> Result<(), TargetError> {
    if family == 4 {
        return if scope.is_some() {
            Err(TargetError::UnexpectedScope)
        } else {
            Ok(())
        };
    }
    let scoped_ranges = [
        (
            u128::from_be_bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            u128::from_be_bytes([
                0xfe, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ]),
        ),
        (
            u128::from_be_bytes([0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            u128::from_be_bytes([
                0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ]),
        ),
        (
            u128::from_be_bytes([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            u128::from_be_bytes([
                0xff, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff,
            ]),
        ),
    ];
    let containing = scoped_ranges
        .iter()
        .any(|(range_start, range_end)| start >= *range_start && end <= *range_end);
    let overlapping = scoped_ranges
        .iter()
        .any(|(range_start, range_end)| start <= *range_end && end >= *range_start);
    if overlapping && !containing {
        return Err(TargetError::CidrCrossesScopeBoundary);
    }
    match (containing, scope) {
        (true, None) => Err(TargetError::MissingIpv6Scope),
        (false, Some(_)) => Err(TargetError::UnexpectedScope),
        _ => Ok(()),
    }
}

fn validate_scope(address: IpAddress, scope: Option<TargetScope>) -> Result<(), TargetError> {
    match (address, requires_scope(address), scope) {
        (IpAddress::V6(_), true, None) => Err(TargetError::MissingIpv6Scope),
        (IpAddress::V4(_), _, Some(_)) | (IpAddress::V6(_), false, Some(_)) => {
            Err(TargetError::UnexpectedScope)
        }
        _ => Ok(()),
    }
}

fn requires_scope(address: IpAddress) -> bool {
    let IpAddress::V6(value) = address else {
        return false;
    };
    let octets = value.octets();
    let link_local_unicast = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
    let local_multicast = octets[0] == 0xff && matches!(octets[1] & 0x0f, 1 | 2);
    link_local_unicast || local_multicast
}

fn address_numeric(address: IpAddress) -> (u8, u128) {
    match address {
        IpAddress::V4(value) => (4, u128::from(u32::from_be_bytes(value.octets()))),
        IpAddress::V6(value) => (6, u128::from_be_bytes(value.octets())),
    }
}

fn numeric_address(family: u8, value: u128) -> Option<IpAddress> {
    match family {
        4 => u32::try_from(value)
            .ok()
            .map(|value| IpAddress::V4(Ipv4Address::new(value.to_be_bytes()))),
        6 => Some(IpAddress::V6(Ipv6Address::new(value.to_be_bytes()))),
        _ => None,
    }
}
