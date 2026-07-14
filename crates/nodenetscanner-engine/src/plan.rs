use nodenet_protocols::ProbePort;

use crate::{
    LogicalProbe, MAX_PORTS_PER_PROBE_FAMILY, MAX_PROBE_DEFINITIONS, PlanError, ProbeFamily,
    TargetSet,
};

/// One explicit probe family and its destination ports, if applicable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDefinition {
    family: ProbeFamily,
    ports: Vec<ProbePort>,
}

impl ProbeDefinition {
    /// Validates explicit ports and canonicalizes their order.
    ///
    /// # Errors
    ///
    /// TCP/UDP require ports; discovery probes forbid them. Duplicate and
    /// excessive port lists are rejected.
    pub fn new(family: ProbeFamily, mut ports: Vec<ProbePort>) -> Result<Self, PlanError> {
        if ports.len() > MAX_PORTS_PER_PROBE_FAMILY {
            return Err(PlanError::TooManyPorts);
        }
        if family.uses_ports() && ports.is_empty() {
            return Err(PlanError::PortsRequired);
        }
        if !family.uses_ports() && !ports.is_empty() {
            return Err(PlanError::PortsNotAllowed);
        }
        ports.sort_unstable();
        if ports.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PlanError::DuplicatePort);
        }
        Ok(Self { family, ports })
    }

    #[must_use]
    pub const fn family(&self) -> ProbeFamily {
        self.family
    }

    #[must_use]
    pub fn ports(&self) -> &[ProbePort] {
        &self.ports
    }

    fn port_factor(&self) -> u64 {
        if self.family.uses_ports() {
            u64::try_from(self.ports.len()).unwrap_or(u64::MAX)
        } else {
            1
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PlanDimension {
    definition: ProbeDefinition,
    compatible_targets: u64,
    end: u64,
}

/// Compact checked target × family × port × attempt product.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanPlan {
    targets: TargetSet,
    dimensions: Vec<PlanDimension>,
    attempts: u32,
    probes_per_attempt: u64,
    logical_probe_count: u64,
}

impl ScanPlan {
    /// Builds the logical product without materializing individual tuples.
    ///
    /// # Errors
    ///
    /// Rejects empty/duplicate/incompatible definitions and every checked-count
    /// overflow before scheduler admission.
    pub fn new(
        targets: TargetSet,
        definitions: Vec<ProbeDefinition>,
        attempts: u32,
    ) -> Result<Self, PlanError> {
        if definitions.is_empty() {
            return Err(PlanError::NoProbes);
        }
        if definitions.len() > MAX_PROBE_DEFINITIONS {
            return Err(PlanError::TooManyProbeDefinitions);
        }
        if attempts == 0 {
            return Err(PlanError::InvalidAttempts);
        }
        let mut seen = [false; MAX_PROBE_DEFINITIONS];
        let mut dimensions = Vec::with_capacity(definitions.len());
        let mut probes_per_attempt = 0_u64;
        for definition in definitions {
            let family_index = family_index(definition.family);
            if seen[family_index] {
                return Err(PlanError::DuplicateProbeFamily);
            }
            seen[family_index] = true;
            let compatible_targets = compatible_target_count(&targets, definition.family);
            if compatible_targets == 0 {
                return Err(PlanError::NoCompatibleTargets);
            }
            let count = compatible_targets
                .checked_mul(definition.port_factor())
                .ok_or(PlanError::LogicalProbeCountOverflow)?;
            probes_per_attempt = probes_per_attempt
                .checked_add(count)
                .ok_or(PlanError::LogicalProbeCountOverflow)?;
            dimensions.push(PlanDimension {
                definition,
                compatible_targets,
                end: probes_per_attempt,
            });
        }
        let logical_probe_count = probes_per_attempt
            .checked_mul(u64::from(attempts))
            .ok_or(PlanError::LogicalProbeCountOverflow)?;
        Ok(Self {
            targets,
            dimensions,
            attempts,
            probes_per_attempt,
            logical_probe_count,
        })
    }

    #[must_use]
    pub const fn logical_probe_count(&self) -> u64 {
        self.logical_probe_count
    }

    #[must_use]
    pub const fn probes_per_attempt(&self) -> u64 {
        self.probes_per_attempt
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    #[must_use]
    pub const fn targets(&self) -> &TargetSet {
        &self.targets
    }

    /// Decodes one product index without allocating a tuple table.
    ///
    /// # Errors
    ///
    /// Rejects an index outside the checked logical product.
    pub fn logical_probe_at(&self, logical_id: u64) -> Result<LogicalProbe, PlanError> {
        if logical_id >= self.logical_probe_count {
            return Err(PlanError::LogicalProbeIndexOutOfRange);
        }
        let attempt_index = logical_id / self.probes_per_attempt;
        let within_attempt = logical_id % self.probes_per_attempt;
        let dimension_index = self
            .dimensions
            .partition_point(|dimension| dimension.end <= within_attempt);
        let dimension = self
            .dimensions
            .get(dimension_index)
            .ok_or(PlanError::LogicalProbeIndexOutOfRange)?;
        let previous_end = dimension_index
            .checked_sub(1)
            .map_or(0, |index| self.dimensions[index].end);
        let local = within_attempt - previous_end;
        let port_factor = dimension.definition.port_factor();
        let target_index = local / port_factor;
        debug_assert!(target_index < dimension.compatible_targets);
        let port = if dimension.definition.family.uses_ports() {
            let port_index = usize::try_from(local % port_factor)
                .map_err(|_| PlanError::LogicalProbeIndexOutOfRange)?;
            Some(dimension.definition.ports[port_index])
        } else {
            None
        };
        let target = compatible_target_at(&self.targets, dimension.definition.family, target_index)
            .ok_or(PlanError::LogicalProbeIndexOutOfRange)?;
        Ok(LogicalProbe {
            logical_id,
            attempt: u32::try_from(attempt_index + 1)
                .map_err(|_| PlanError::LogicalProbeIndexOutOfRange)?,
            target,
            family: dimension.definition.family,
            port,
        })
    }
}

const fn family_index(family: ProbeFamily) -> usize {
    match family {
        ProbeFamily::Arp => 0,
        ProbeFamily::Ndp => 1,
        ProbeFamily::Icmpv4Echo => 2,
        ProbeFamily::Icmpv6Echo => 3,
        ProbeFamily::TcpSyn => 4,
        ProbeFamily::Udp => 5,
    }
}

fn compatible_target_count(targets: &TargetSet, family: ProbeFamily) -> u64 {
    match (family.supports_ipv4(), family.supports_ipv6()) {
        (true, true) => targets.ipv4_count() + targets.ipv6_count(),
        (true, false) => targets.ipv4_count(),
        (false, true) => targets.ipv6_count(),
        (false, false) => 0,
    }
}

fn compatible_target_at(
    targets: &TargetSet,
    family: ProbeFamily,
    index: u64,
) -> Option<crate::ScanTarget> {
    if family.supports_ipv4() {
        if index < targets.ipv4_count() {
            return targets.target_at_family(4, index);
        }
        if family.supports_ipv6() {
            return targets.target_at_family(6, index - targets.ipv4_count());
        }
        return None;
    }
    if family.supports_ipv6() {
        targets.target_at_family(6, index)
    } else {
        None
    }
}
