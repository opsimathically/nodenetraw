use std::net::IpAddr;
use std::time::Duration;

use napi_derive::napi;
use nodenet_protocols::{IpAddress, Ipv4Address, Ipv6Address, ProbePort};
use nodenetscanner_engine::{
    DiscoverySilencePolicy, ProbeDefinition, ProbeFamily, ScanDuration, ScanPlan, SchedulerConfig,
    TargetCidr, TargetEndpoint, TargetInput, TargetIntervalInput, TargetScope, TargetSet,
    TimingMode,
};

use crate::error::ScannerError;

pub(crate) const MAX_BATCH_RESULTS: u32 = 4_096;
pub(crate) const DEFAULT_BATCH_RESULTS: u32 = 512;
pub(crate) const DEFAULT_SOURCE_PORT_START: u16 = 49_152;
pub(crate) const DEFAULT_SOURCE_PORT_END: u16 = 65_535;

#[napi(object)]
#[derive(Clone)]
pub struct NativeScanTarget {
    pub cidr: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativePortSelection {
    pub start: u32,
    pub end: u32,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeScanProbe {
    pub kind: String,
    pub family: Option<String>,
    pub ports: Option<Vec<NativePortSelection>>,
    pub payload: Option<Vec<u8>>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeRateOptions {
    pub packets_per_second: Option<u32>,
    pub burst: Option<u32>,
    pub max_outstanding: Option<u32>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeTimingOptions {
    pub timeout_ms: Option<u32>,
    pub minimum_timeout_ms: Option<u32>,
    pub maximum_timeout_ms: Option<u32>,
    pub retries: Option<u32>,
    pub fixed: Option<bool>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeVlanOptions {
    pub identifier: u32,
    pub priority: Option<u32>,
    pub drop_eligible: Option<bool>,
}

#[napi(object)]
#[derive(Clone)]
pub struct NativeScanPlan {
    pub targets: Vec<NativeScanTarget>,
    pub exclude: Option<Vec<NativeScanTarget>>,
    pub probes: Vec<NativeScanProbe>,
    pub deadline_ms: u32,
    pub rate: Option<NativeRateOptions>,
    pub timing: Option<NativeTimingOptions>,
    pub seed: Option<String>,
    pub source_address: Option<String>,
    pub interface: Option<String>,
    pub vlan: Option<NativeVlanOptions>,
    pub source_port_start: Option<u32>,
    pub source_port_end: Option<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct VlanOverride {
    pub identifier: u16,
    pub priority: u8,
    pub drop_eligible: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionOptions {
    pub udp_payload_v4: Vec<u8>,
    pub udp_payload_v6: Vec<u8>,
    pub source_address: Option<IpAddr>,
    pub interface: Option<String>,
    pub vlan: Option<VlanOverride>,
    pub source_port_start: u16,
    pub source_port_end: u16,
    pub seed: u64,
    pub late_grace: Duration,
}

#[derive(Clone)]
pub(crate) struct ValidatedPlan {
    pub plan: ScanPlan,
    pub scheduler: SchedulerConfig,
    pub options: SessionOptions,
}

impl NativeScanPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "one pre-admission transaction enforces every independent public limit"
    )]
    pub(crate) fn validate(self) -> Result<ValidatedPlan, ScannerError> {
        if self.deadline_ms == 0 {
            return Err(ScannerError::invalid(
                "validate scan plan",
                "deadlineMs must be greater than zero",
            ));
        }
        let includes = parse_targets(&self.targets)?;
        let excludes = parse_targets(self.exclude.as_deref().unwrap_or_default())?;
        let targets = TargetSet::normalize(&includes, &excludes).map_err(|error| {
            ScannerError::invalid("validate scan targets", format!("{error:?}"))
        })?;

        let mut definitions = Vec::new();
        let mut udp_payload_v4 = Vec::new();
        let mut udp_payload_v6 = Vec::new();
        for probe in self.probes {
            let (family, ports, payload) = parse_probe(probe)?;
            if family == ProbeFamily::Udp {
                match payload.0 {
                    UdpPayloadFamily::Both => {
                        udp_payload_v4.clone_from(&payload.1);
                        udp_payload_v6 = payload.1;
                    }
                    UdpPayloadFamily::Ipv4 => udp_payload_v4 = payload.1,
                    UdpPayloadFamily::Ipv6 => udp_payload_v6 = payload.1,
                    UdpPayloadFamily::None => {}
                }
            }
            definitions.push(ProbeDefinition::new(family, ports).map_err(|error| {
                ScannerError::invalid("validate scan probes", format!("{error:?}"))
            })?);
        }

        let timing = self.timing.unwrap_or(NativeTimingOptions {
            timeout_ms: None,
            minimum_timeout_ms: None,
            maximum_timeout_ms: None,
            retries: None,
            fixed: None,
        });
        let retries = timing.retries.unwrap_or(1);
        let plan = ScanPlan::new(targets, definitions, 1)
            .map_err(|error| ScannerError::invalid("validate scan probes", format!("{error:?}")))?;

        let rate = self.rate.unwrap_or(NativeRateOptions {
            packets_per_second: None,
            burst: None,
            max_outstanding: None,
        });
        let max_outstanding = usize::try_from(rate.max_outstanding.unwrap_or(4_096))
            .map_err(|_| ScannerError::invalid("validate rate", "maxOutstanding is too large"))?;
        let initial_timeout = timing.timeout_ms.unwrap_or(1_000);
        let minimum_timeout = timing
            .minimum_timeout_ms
            .unwrap_or(initial_timeout.min(100));
        let maximum_timeout = timing
            .maximum_timeout_ms
            .unwrap_or(initial_timeout.max(10_000));
        let scheduler = SchedulerConfig {
            rate_per_second: rate.packets_per_second.unwrap_or(100),
            burst: rate
                .burst
                .unwrap_or_else(|| u32::try_from(max_outstanding.min(32)).unwrap_or(1)),
            max_outstanding,
            max_retransmissions: u8::try_from(retries).map_err(|_| {
                ScannerError::invalid("validate timing", "retries must not exceed 10")
            })?,
            initial_timeout: duration_ms(initial_timeout),
            minimum_timeout: duration_ms(minimum_timeout),
            maximum_timeout: duration_ms(maximum_timeout),
            session_deadline: duration_ms(self.deadline_ms),
            late_grace: duration_ms(maximum_timeout),
            max_grace_entries: max_outstanding,
            max_per_target: max_outstanding.clamp(1, 64),
            max_per_prefix: max_outstanding.clamp(1, 1_024),
            timing_mode: if timing.fixed.unwrap_or(false) {
                TimingMode::FixedRate
            } else {
                TimingMode::Adaptive
            },
            discovery_silence: DiscoverySilencePolicy::Unknown,
            tcp_reset_cleanup: false,
        }
        .validate()
        .map_err(|error| ScannerError::invalid("validate scheduler", format!("{error:?}")))?;

        let source_address = self
            .source_address
            .map(|value| parse_plain_address(&value, "sourceAddress"))
            .transpose()?;
        let source_port_start = checked_port(
            self.source_port_start
                .unwrap_or(u32::from(DEFAULT_SOURCE_PORT_START)),
            "sourcePortRange.start",
        )?;
        let source_port_end = checked_port(
            self.source_port_end
                .unwrap_or(u32::from(DEFAULT_SOURCE_PORT_END)),
            "sourcePortRange.end",
        )?;
        if source_port_start > source_port_end {
            return Err(ScannerError::invalid(
                "validate source port range",
                "source port range is reversed",
            ));
        }
        let vlan = self.vlan.as_ref().map(validate_vlan).transpose()?;
        let seed = self.seed.map_or(Ok(0), |value| {
            value.parse::<u64>().map_err(|_| {
                ScannerError::invalid("validate seed", "seed must fit an unsigned 64-bit integer")
            })
        })?;

        Ok(ValidatedPlan {
            plan,
            scheduler,
            options: SessionOptions {
                udp_payload_v4,
                udp_payload_v6,
                source_address,
                interface: self.interface,
                vlan,
                source_port_start,
                source_port_end,
                seed,
                late_grace: Duration::from_millis(u64::from(maximum_timeout)),
            },
        })
    }
}

fn duration_ms(value: u32) -> ScanDuration {
    ScanDuration::from_micros(u64::from(value) * 1_000)
}

fn checked_port(value: u32, field: &str) -> Result<u16, ScannerError> {
    let value = u16::try_from(value).map_err(|_| {
        ScannerError::invalid(
            "validate port",
            format!("{field} must be from 1 through 65535"),
        )
    })?;
    if value == 0 {
        return Err(ScannerError::invalid(
            "validate port",
            format!("{field} must be from 1 through 65535"),
        ));
    }
    Ok(value)
}

fn validate_vlan(value: &NativeVlanOptions) -> Result<VlanOverride, ScannerError> {
    if value.identifier == 0 || value.identifier > 4_094 {
        return Err(ScannerError::invalid(
            "validate VLAN",
            "VLAN identifier must be from 1 through 4094",
        ));
    }
    let priority = value.priority.unwrap_or(0);
    if priority > 7 {
        return Err(ScannerError::invalid(
            "validate VLAN",
            "VLAN priority must be from 0 through 7",
        ));
    }
    Ok(VlanOverride {
        identifier: u16::try_from(value.identifier).unwrap_or_default(),
        priority: u8::try_from(priority).unwrap_or_default(),
        drop_eligible: value.drop_eligible.unwrap_or(false),
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UdpPayloadFamily {
    None,
    Both,
    Ipv4,
    Ipv6,
}

type ParsedProbe = (ProbeFamily, Vec<ProbePort>, (UdpPayloadFamily, Vec<u8>));

fn parse_probe(probe: NativeScanProbe) -> Result<ParsedProbe, ScannerError> {
    let payload = probe.payload.unwrap_or_default();
    if payload.len() > 1_048_576 {
        return Err(ScannerError::resource(
            "validate UDP payload",
            "UDP payload exceeds the 1 MiB session template budget",
        ));
    }
    let ports = expand_ports(probe.ports.as_deref().unwrap_or_default())?;
    let family = match (probe.kind.as_str(), probe.family.as_deref()) {
        ("arp", None) => ProbeFamily::Arp,
        ("ndp", None) => ProbeFamily::Ndp,
        ("icmpEcho", Some("ipv4")) => ProbeFamily::Icmpv4Echo,
        ("icmpEcho", Some("ipv6")) => ProbeFamily::Icmpv6Echo,
        ("tcpSyn", None) => ProbeFamily::TcpSyn,
        ("udp", None | Some("both" | "ipv4" | "ipv6")) => ProbeFamily::Udp,
        _ => {
            return Err(ScannerError::invalid(
                "validate scan probe",
                "unsupported probe kind/family combination",
            ));
        }
    };
    if family != ProbeFamily::Udp && !payload.is_empty() {
        return Err(ScannerError::invalid(
            "validate scan probe",
            "payload is supported only for UDP probes",
        ));
    }
    let payload_family = if family != ProbeFamily::Udp || payload.is_empty() {
        UdpPayloadFamily::None
    } else {
        match probe.family.as_deref() {
            Some("ipv4") => UdpPayloadFamily::Ipv4,
            Some("ipv6") => UdpPayloadFamily::Ipv6,
            _ => UdpPayloadFamily::Both,
        }
    };
    Ok((family, ports, (payload_family, payload)))
}

fn expand_ports(values: &[NativePortSelection]) -> Result<Vec<ProbePort>, ScannerError> {
    let mut ports = Vec::new();
    for value in values {
        let start = checked_port(value.start, "port.start")?;
        let end = checked_port(value.end, "port.end")?;
        if start > end {
            return Err(ScannerError::invalid(
                "validate ports",
                "port range is reversed",
            ));
        }
        let additional = usize::from(end - start) + 1;
        if ports.len().saturating_add(additional) > 65_536 {
            return Err(ScannerError::resource(
                "validate ports",
                "a probe family may contain at most 65536 ports",
            ));
        }
        for port in start..=end {
            ports.push(ProbePort::new(port)?);
        }
    }
    Ok(ports)
}

fn parse_targets(values: &[NativeScanTarget]) -> Result<Vec<TargetInput>, ScannerError> {
    values.iter().map(parse_target).collect()
}

fn parse_target(value: &NativeScanTarget) -> Result<TargetInput, ScannerError> {
    match (&value.cidr, &value.start, &value.end) {
        (Some(cidr), None, None) => {
            let (address, prefix) = cidr.rsplit_once('/').ok_or_else(|| {
                ScannerError::invalid("validate target", "CIDR target requires a prefix length")
            })?;
            let endpoint = parse_endpoint(address)?;
            let prefix_length = prefix.parse::<u8>().map_err(|_| {
                ScannerError::invalid("validate target", "invalid CIDR prefix length")
            })?;
            Ok(TargetInput::Cidr(TargetCidr {
                network: endpoint,
                prefix_length,
            }))
        }
        (None, Some(start), Some(end)) => Ok(TargetInput::Range(TargetIntervalInput {
            start: parse_endpoint(start)?,
            end: parse_endpoint(end)?,
        })),
        _ => Err(ScannerError::invalid(
            "validate target",
            "target must contain exactly cidr or start/end",
        )),
    }
}

fn parse_endpoint(value: &str) -> Result<TargetEndpoint, ScannerError> {
    let (address, scope) = match value.rsplit_once('%') {
        Some((address, scope)) => {
            let value = scope.parse::<u32>().map_err(|_| {
                ScannerError::invalid(
                    "validate target",
                    "IPv6 zones must be numeric interface indices",
                )
            })?;
            (
                address,
                Some(TargetScope::new(value).map_err(|error| {
                    ScannerError::invalid("validate target", format!("{error:?}"))
                })?),
            )
        }
        None => (value, None),
    };
    let address = parse_plain_address(address, "target")?;
    TargetEndpoint::new(to_protocol_address(address), scope)
        .map_err(|error| ScannerError::invalid("validate target", format!("{error:?}")))
}

fn parse_plain_address(value: &str, field: &str) -> Result<IpAddr, ScannerError> {
    value.parse::<IpAddr>().map_err(|_| {
        ScannerError::invalid(
            "validate address",
            format!("{field} is not an IPv4/IPv6 address"),
        )
    })
}

pub(crate) fn to_protocol_address(value: IpAddr) -> IpAddress {
    match value {
        IpAddr::V4(value) => IpAddress::V4(Ipv4Address::from(value)),
        IpAddr::V6(value) => IpAddress::V6(Ipv6Address::from(value)),
    }
}

pub(crate) fn to_std_address(value: IpAddress) -> IpAddr {
    match value {
        IpAddress::V4(value) => IpAddr::V4(value.into()),
        IpAddress::V6(value) => IpAddr::V6(value.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_plan_validation_rejects_implicit_or_reversed_inputs() {
        let empty = NativeScanPlan {
            targets: Vec::new(),
            exclude: None,
            probes: Vec::new(),
            deadline_ms: 1,
            rate: None,
            timing: None,
            seed: None,
            source_address: None,
            interface: None,
            vlan: None,
            source_port_start: None,
            source_port_end: None,
        };
        assert!(empty.validate().is_err());
        assert!(expand_ports(&[NativePortSelection { start: 2, end: 1 }]).is_err());
    }
}
