use crate::{IpProtocol, Ipv4Address, Ipv6Address};

/// Source/destination addresses used by TCP, UDP, and `ICMPv6` pseudo-headers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportChecksumContext {
    Ipv4 {
        source: Ipv4Address,
        destination: Ipv4Address,
    },
    Ipv6 {
        source: Ipv6Address,
        destination: Ipv6Address,
    },
}

/// Computes the RFC 1071 one's-complement Internet checksum.
#[must_use]
pub fn compute_internet_checksum(input: &[u8]) -> u16 {
    let mut accumulator = InternetChecksumAccumulator::default();
    accumulator.update(input);
    accumulator.finish()
}

/// Returns whether a complete checksummed byte sequence folds to all ones.
#[must_use]
pub fn validate_internet_checksum(input: &[u8]) -> bool {
    compute_internet_checksum(input) == 0
}

/// Computes a transport checksum including its IPv4 or IPv6 pseudo-header.
///
/// Returns `None` when the segment length cannot be represented by the selected
/// IP pseudo-header. Callers must write a zero checksum field before invoking
/// this function.
#[must_use]
pub fn compute_transport_checksum(
    context: TransportChecksumContext,
    protocol: IpProtocol,
    segment: &[u8],
) -> Option<u16> {
    let mut accumulator = InternetChecksumAccumulator::default();
    match context {
        TransportChecksumContext::Ipv4 {
            source,
            destination,
        } => {
            let length = u16::try_from(segment.len()).ok()?;
            accumulator.update(&source.octets());
            accumulator.update(&destination.octets());
            accumulator.update(&[0, protocol.get()]);
            accumulator.update(&length.to_be_bytes());
        }
        TransportChecksumContext::Ipv6 {
            source,
            destination,
        } => {
            let length = u32::try_from(segment.len()).ok()?;
            accumulator.update(&source.octets());
            accumulator.update(&destination.octets());
            accumulator.update(&length.to_be_bytes());
            accumulator.update(&[0, 0, 0, protocol.get()]);
        }
    }
    accumulator.update(segment);
    Some(accumulator.finish())
}

/// Validates a complete checksummed transport segment and pseudo-header.
#[must_use]
pub fn validate_transport_checksum(
    context: TransportChecksumContext,
    protocol: IpProtocol,
    segment: &[u8],
) -> bool {
    compute_transport_checksum(context, protocol, segment) == Some(0)
}

#[derive(Default)]
struct InternetChecksumAccumulator {
    sum: u32,
    pending_high_byte: Option<u8>,
}

impl InternetChecksumAccumulator {
    fn update(&mut self, mut input: &[u8]) {
        if let Some(high) = self.pending_high_byte.take() {
            if let Some((&low, rest)) = input.split_first() {
                self.add_word(u16::from_be_bytes([high, low]));
                input = rest;
            } else {
                self.pending_high_byte = Some(high);
                return;
            }
        }
        let mut chunks = input.chunks_exact(2);
        for chunk in &mut chunks {
            self.add_word(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let [last] = chunks.remainder() {
            self.pending_high_byte = Some(*last);
        }
    }

    fn add_word(&mut self, word: u16) {
        self.sum += u32::from(word);
        self.sum = (self.sum & 0xffff) + (self.sum >> 16);
    }

    fn finish(mut self) -> u16 {
        if let Some(high) = self.pending_high_byte {
            self.add_word(u16::from(high) << 8);
        }
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        let bytes = self.sum.to_be_bytes();
        !u16::from_be_bytes([bytes[2], bytes[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_rfc_vector() {
        let bytes = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(compute_internet_checksum(&bytes), 0x220d);
        assert_eq!(compute_internet_checksum(&[0x01]), 0xfeff);
    }

    #[test]
    fn segmented_accumulation_preserves_odd_byte_alignment() {
        let context = TransportChecksumContext::Ipv6 {
            source: Ipv6Address::new([0; 16]),
            destination: Ipv6Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        };
        let segment = [1, 2, 3, 4, 5];
        assert!(compute_transport_checksum(context, IpProtocol::new(58), &segment).is_some());
    }
}
