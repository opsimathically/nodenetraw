use crate::{
    BuildError, Field, Ipv4Address, Ipv6Address, MAX_TEMPLATE_PATCH_DESCRIPTORS, MacAddress,
    PacketKind, PacketLength,
};

/// Semantic field represented by a checked template patch descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PatchKind {
    DestinationMac,
    SourceMac,
    SourceIpv4,
    DestinationIpv4,
    SourceIpv6,
    DestinationIpv6,
    Ipv4TotalLength,
    Ipv4Identification,
    Ipv4HeaderChecksum,
    Ipv6PayloadLength,
    Ipv6FragmentIdentification,
    Token,
}

impl PatchKind {
    const fn fixed_length(self) -> Option<usize> {
        match self {
            Self::DestinationMac | Self::SourceMac => Some(6),
            Self::SourceIpv4 | Self::DestinationIpv4 | Self::Ipv6FragmentIdentification => Some(4),
            Self::SourceIpv6 | Self::DestinationIpv6 => Some(16),
            Self::Ipv4TotalLength
            | Self::Ipv4Identification
            | Self::Ipv4HeaderChecksum
            | Self::Ipv6PayloadLength => Some(2),
            Self::Token => None,
        }
    }
}

/// One immutable checked field location in a frame template.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PatchDescriptor {
    kind: PatchKind,
    offset: usize,
    length: usize,
}

impl PatchDescriptor {
    /// Creates and bounds a descriptor against its template length.
    ///
    /// # Errors
    ///
    /// Returns an invalid descriptor error for overflow, out-of-bounds spans,
    /// incorrect fixed widths, or token widths outside 1 through 32 bytes.
    pub const fn new(
        kind: PatchKind,
        offset: usize,
        length: usize,
        template_length: usize,
    ) -> Result<Self, BuildError> {
        let Some(end) = offset.checked_add(length) else {
            return Err(BuildError::ArithmeticOverflow {
                field: Field::TemplateDescriptor,
            });
        };
        if end > template_length {
            return Err(BuildError::InvalidValue {
                field: Field::TemplateDescriptor,
            });
        }
        match kind.fixed_length() {
            Some(expected) if length != expected => {
                return Err(BuildError::InvalidValue {
                    field: Field::TemplateDescriptor,
                });
            }
            None if length == 0 || length > 32 => {
                return Err(BuildError::InvalidValue {
                    field: Field::TemplateDescriptor,
                });
            }
            _ => {}
        }
        Ok(Self {
            kind,
            offset,
            length,
        })
    }

    #[must_use]
    pub const fn kind(self) -> PatchKind {
        self.kind
    }

    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    #[must_use]
    pub const fn length(self) -> usize {
        self.length
    }
}

/// A typed patch value, encoded in network byte order where applicable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchValue<'a> {
    Mac(MacAddress),
    Ipv4(Ipv4Address),
    Ipv6(Ipv6Address),
    U16(u16),
    U32(u32),
    Bytes(&'a [u8]),
}

/// One requested patch identified by descriptor index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TemplatePatch<'a> {
    pub descriptor_index: usize,
    pub value: PatchValue<'a>,
}

/// An immutable bounded frame plus checked mutable field descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameTemplate {
    bytes: Vec<u8>,
    kind: PacketKind,
    descriptors: Box<[PatchDescriptor]>,
}

impl FrameTemplate {
    /// Copies a validated frame and its non-overlapping descriptors.
    ///
    /// # Errors
    ///
    /// Returns before allocation for packet length, descriptor count/bounds,
    /// or overlapping descriptor errors.
    pub fn new(
        bytes: &[u8],
        kind: PacketKind,
        descriptors: &[PatchDescriptor],
    ) -> Result<Self, BuildError> {
        PacketLength::new(bytes.len(), kind)?;
        if descriptors.len() > MAX_TEMPLATE_PATCH_DESCRIPTORS {
            return Err(BuildError::InvalidValue {
                field: Field::TemplateDescriptor,
            });
        }
        for (index, descriptor) in descriptors.iter().copied().enumerate() {
            let end = descriptor.offset.checked_add(descriptor.length).ok_or(
                BuildError::ArithmeticOverflow {
                    field: Field::TemplateDescriptor,
                },
            )?;
            if end > bytes.len() {
                return Err(BuildError::InvalidValue {
                    field: Field::TemplateDescriptor,
                });
            }
            for other in descriptors.iter().copied().take(index) {
                let other_end = other.offset + other.length;
                if descriptor.offset < other_end && other.offset < end {
                    return Err(BuildError::InvalidValue {
                        field: Field::TemplateDescriptor,
                    });
                }
            }
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            kind,
            descriptors: descriptors.to_vec().into_boxed_slice(),
        })
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn kind(&self) -> PacketKind {
        self.kind
    }

    #[must_use]
    pub fn descriptors(&self) -> &[PatchDescriptor] {
        &self.descriptors
    }

    /// Copies and patches into caller-owned storage transactionally.
    ///
    /// # Errors
    ///
    /// Returns before modifying `output` for short capacity, invalid/duplicate
    /// indices, or a patch value that does not match its descriptor.
    pub fn instantiate_into<'output>(
        &self,
        output: &'output mut [u8],
        patches: &[TemplatePatch<'_>],
    ) -> Result<&'output mut [u8], BuildError> {
        self.validate_patches(patches)?;
        if output.len() < self.bytes.len() {
            return Err(BuildError::BufferTooSmall {
                required: self.bytes.len(),
                actual: output.len(),
            });
        }
        let encoded = &mut output[..self.bytes.len()];
        encoded.copy_from_slice(&self.bytes);
        self.apply_patches(encoded, patches);
        Ok(encoded)
    }

    /// Creates an exactly sized patched frame after validating every patch.
    ///
    /// # Errors
    ///
    /// Returns patch validation errors before allocating.
    pub fn instantiate(&self, patches: &[TemplatePatch<'_>]) -> Result<Vec<u8>, BuildError> {
        self.validate_patches(patches)?;
        let mut encoded = self.bytes.clone();
        self.apply_patches(&mut encoded, patches);
        Ok(encoded)
    }

    fn validate_patches(&self, patches: &[TemplatePatch<'_>]) -> Result<(), BuildError> {
        if patches.len() > self.descriptors.len() {
            return Err(BuildError::InvalidValue {
                field: Field::TemplatePatch,
            });
        }
        let mut seen = [false; MAX_TEMPLATE_PATCH_DESCRIPTORS];
        for patch in patches {
            let Some(descriptor) = self.descriptors.get(patch.descriptor_index).copied() else {
                return Err(BuildError::InvalidValue {
                    field: Field::TemplatePatch,
                });
            };
            if seen[patch.descriptor_index] || !patch_matches(descriptor, patch.value) {
                return Err(BuildError::InvalidValue {
                    field: Field::TemplatePatch,
                });
            }
            seen[patch.descriptor_index] = true;
        }
        Ok(())
    }

    fn apply_patches(&self, output: &mut [u8], patches: &[TemplatePatch<'_>]) {
        for patch in patches {
            let descriptor = self.descriptors[patch.descriptor_index];
            let destination = &mut output[descriptor.offset..descriptor.offset + descriptor.length];
            match patch.value {
                PatchValue::Mac(value) => destination.copy_from_slice(&value.octets()),
                PatchValue::Ipv4(value) => destination.copy_from_slice(&value.octets()),
                PatchValue::Ipv6(value) => destination.copy_from_slice(&value.octets()),
                PatchValue::U16(value) => destination.copy_from_slice(&value.to_be_bytes()),
                PatchValue::U32(value) => destination.copy_from_slice(&value.to_be_bytes()),
                PatchValue::Bytes(value) => destination.copy_from_slice(value),
            }
        }
    }
}

#[allow(
    clippy::match_same_arms,
    reason = "the explicit type matrix keeps every patch-kind pairing auditable"
)]
const fn patch_matches(descriptor: PatchDescriptor, value: PatchValue<'_>) -> bool {
    match (descriptor.kind, value) {
        (PatchKind::DestinationMac | PatchKind::SourceMac, PatchValue::Mac(_)) => true,
        (PatchKind::SourceIpv4 | PatchKind::DestinationIpv4, PatchValue::Ipv4(_)) => true,
        (PatchKind::SourceIpv6 | PatchKind::DestinationIpv6, PatchValue::Ipv6(_)) => true,
        (
            PatchKind::Ipv4TotalLength
            | PatchKind::Ipv4Identification
            | PatchKind::Ipv4HeaderChecksum
            | PatchKind::Ipv6PayloadLength,
            PatchValue::U16(_),
        ) => true,
        (PatchKind::Ipv6FragmentIdentification, PatchValue::U32(_)) => true,
        (PatchKind::Token, PatchValue::Bytes(bytes)) => bytes.len() == descriptor.length,
        _ => false,
    }
}
