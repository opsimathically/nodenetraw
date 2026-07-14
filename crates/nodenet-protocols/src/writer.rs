use crate::{BuildError, PacketKind, PacketLength};

/// A prevalidated immutable packet construction plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketPlan<'a> {
    bytes: &'a [u8],
    length: PacketLength,
}

impl<'a> PacketPlan<'a> {
    /// Validates the required encoded length without allocating or writing.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::LengthExceedsLimit`] before allocation when the
    /// encoded packet exceeds the selected wire-format ceiling.
    pub const fn new(bytes: &'a [u8], kind: PacketKind) -> Result<Self, BuildError> {
        let length = match PacketLength::new(bytes.len(), kind) {
            Ok(length) => length,
            Err(error) => return Err(error),
        };
        Ok(Self { bytes, length })
    }

    /// Reports the exact required output length before writing.
    #[must_use]
    pub const fn required_length(self) -> PacketLength {
        self.length
    }

    /// Copies into a caller-owned buffer after every fallible check succeeds.
    ///
    /// On error, `output` is left byte-for-byte unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::BufferTooSmall`] before writing when `output`
    /// cannot hold the complete planned packet.
    pub fn write_into(self, output: &mut [u8]) -> Result<&mut [u8], BuildError> {
        let required = self.length.get();
        if output.len() < required {
            return Err(BuildError::BufferTooSmall {
                required,
                actual: output.len(),
            });
        }
        let encoded = &mut output[..required];
        encoded.copy_from_slice(self.bytes);
        Ok(encoded)
    }

    /// Constructs an exactly sized owned packet for control and test paths.
    #[must_use]
    pub fn to_owned(self) -> OwnedPacket {
        OwnedPacket {
            bytes: self.bytes.to_vec(),
            kind: self.length.kind(),
        }
    }
}

/// An owned, length-checked encoded packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPacket {
    bytes: Vec<u8>,
    kind: PacketKind,
}

impl OwnedPacket {
    /// Returns the encoded packet bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the packet's enclosing wire kind.
    #[must_use]
    pub const fn kind(&self) -> PacketKind {
        self.kind
    }

    /// Transfers ownership of the exactly sized byte vector.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}
