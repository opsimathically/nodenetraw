use crate::{EngineError, EntropySource, SchedulingSeed};

/// A deterministic affine permutation over `[0, length)`.
///
/// The multiplier is derived from `SplitMix64` output and made coprime to the
/// exact logical length, making the mapping bijective without storing indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeededPermutation {
    length: u64,
    multiplier: u64,
    offset: u64,
    seed: SchedulingSeed,
}

impl SeededPermutation {
    /// Constructs a reproducible permutation for a nonempty product.
    ///
    /// # Errors
    ///
    /// Rejects an empty logical product.
    pub fn new(length: u64, seed: SchedulingSeed) -> Result<Self, EngineError> {
        if length == 0 {
            return Err(crate::PlanError::NoProbes.into());
        }
        if length == 1 {
            return Ok(Self {
                length,
                multiplier: 0,
                offset: 0,
                seed,
            });
        }
        let mut state = seed.value();
        let offset = splitmix64(&mut state) % length;
        let mut multiplier = splitmix64(&mut state) % length;
        if multiplier == 0 {
            multiplier = 1;
        }
        while gcd(multiplier, length) != 1 {
            multiplier = if multiplier + 1 == length {
                1
            } else {
                multiplier + 1
            };
        }
        Ok(Self {
            length,
            multiplier,
            offset,
            seed,
        })
    }

    /// Obtains a scheduling seed through the injected entropy boundary.
    ///
    /// # Errors
    ///
    /// Propagates entropy or empty-product failure.
    pub fn from_entropy(
        length: u64,
        entropy: &mut impl EntropySource,
        report: bool,
    ) -> Result<Self, EngineError> {
        let value = entropy.scheduling_seed()?;
        Self::new(length, SchedulingSeed::Generated { value, report })
    }

    #[must_use]
    pub const fn length(self) -> u64 {
        self.length
    }

    #[must_use]
    pub const fn reported_seed(self) -> Option<u64> {
        self.seed.reported()
    }

    /// Maps one ordinal bijectively into the logical product.
    #[must_use]
    pub fn permute(self, ordinal: u64) -> Option<u64> {
        if ordinal >= self.length {
            return None;
        }
        if self.length == 1 {
            return Some(0);
        }
        let value = (u128::from(self.multiplier) * u128::from(ordinal) + u128::from(self.offset))
            % u128::from(self.length);
        u64::try_from(value).ok()
    }
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}
