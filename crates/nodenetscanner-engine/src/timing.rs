use crate::{
    ConfigError, EngineError, MAX_OUTSTANDING_PROBES, MAX_TRANSMIT_RATE_PER_SECOND, MonotonicTime,
    ScanDuration, TimingMode,
};

const TOKEN_SCALE: u128 = 1_000_000;

/// Exact fixed-point packet token bucket driven only by injected monotonic time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenBucket {
    rate_per_second: u32,
    capacity_scaled: u128,
    tokens_scaled: u128,
    last_refill: MonotonicTime,
}

impl TokenBucket {
    /// Creates a checked token bucket at one monotonic instant.
    ///
    /// # Errors
    ///
    /// Rejects zero or above-ceiling rates and burst sizes.
    pub fn new(rate_per_second: u32, burst: u32, now: MonotonicTime) -> Result<Self, ConfigError> {
        if rate_per_second == 0 || rate_per_second > MAX_TRANSMIT_RATE_PER_SECOND {
            return Err(ConfigError::InvalidRate);
        }
        if burst == 0 || usize::try_from(burst).unwrap_or(usize::MAX) > MAX_OUTSTANDING_PROBES {
            return Err(ConfigError::InvalidBurst);
        }
        let capacity_scaled = u128::from(burst) * TOKEN_SCALE;
        Ok(Self {
            rate_per_second,
            capacity_scaled,
            tokens_scaled: capacity_scaled,
            last_refill: now,
        })
    }

    /// Charges one emitted frame when a token is available.
    ///
    /// # Errors
    ///
    /// Rejects a clock that moved backwards.
    pub fn try_take(&mut self, now: MonotonicTime) -> Result<bool, EngineError> {
        self.refill(now)?;
        if self.tokens_scaled < TOKEN_SCALE {
            return Ok(false);
        }
        self.tokens_scaled -= TOKEN_SCALE;
        Ok(true)
    }

    /// Returns the exact earliest whole-microsecond token boundary.
    ///
    /// # Errors
    ///
    /// Rejects a clock that moved backwards or deadline arithmetic overflow.
    pub fn next_ready(&mut self, now: MonotonicTime) -> Result<MonotonicTime, EngineError> {
        self.refill(now)?;
        if self.tokens_scaled >= TOKEN_SCALE {
            return Ok(now);
        }
        let deficit = TOKEN_SCALE - self.tokens_scaled;
        let rate = u128::from(self.rate_per_second);
        let micros = deficit.div_ceil(rate);
        let micros = u64::try_from(micros).map_err(|_| EngineError::DeadlineOverflow)?;
        now.checked_add(ScanDuration::from_micros(micros))
            .ok_or(EngineError::DeadlineOverflow)
    }

    fn refill(&mut self, now: MonotonicTime) -> Result<(), EngineError> {
        let elapsed = now
            .elapsed_since(self.last_refill)
            .ok_or(EngineError::ClockRegressed)?;
        let added = u128::from(elapsed.as_micros()) * u128::from(self.rate_per_second);
        self.tokens_scaled = self
            .tokens_scaled
            .saturating_add(added)
            .min(self.capacity_scaled);
        self.last_refill = now;
        Ok(())
    }
}

/// Integer RFC-6298-style smoothed RTT and variance estimator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RttEstimator {
    smoothed: Option<ScanDuration>,
    variation: ScanDuration,
    samples: u64,
}

impl RttEstimator {
    pub fn observe(&mut self, sample: ScanDuration) {
        if sample == ScanDuration::ZERO {
            return;
        }
        let sample = sample.as_micros();
        match self.smoothed {
            None => {
                self.smoothed = Some(ScanDuration::from_micros(sample));
                self.variation = ScanDuration::from_micros(sample / 2);
            }
            Some(smoothed) => {
                let smoothed = smoothed.as_micros();
                let variation = self.variation.as_micros();
                let difference = smoothed.abs_diff(sample);
                self.variation = ScanDuration::from_micros(
                    variation.saturating_mul(3).saturating_add(difference) / 4,
                );
                self.smoothed = Some(ScanDuration::from_micros(
                    smoothed.saturating_mul(7).saturating_add(sample) / 8,
                ));
            }
        }
        self.samples = self.samples.saturating_add(1);
    }

    /// Calculates the bounded timeout for the selected timing mode.
    ///
    /// # Errors
    ///
    /// Rejects a zero or inconsistently ordered timeout range.
    pub fn timeout(
        self,
        mode: TimingMode,
        fallback: ScanDuration,
        minimum: ScanDuration,
        maximum: ScanDuration,
    ) -> Result<ScanDuration, ConfigError> {
        if fallback == ScanDuration::ZERO
            || minimum == ScanDuration::ZERO
            || minimum > fallback
            || fallback > maximum
        {
            return Err(ConfigError::InvalidTimeout);
        }
        if matches!(mode, TimingMode::FixedRate) {
            return Ok(fallback);
        }
        let Some(smoothed) = self.smoothed else {
            return Ok(fallback);
        };
        let value = smoothed
            .as_micros()
            .saturating_add(self.variation.as_micros().saturating_mul(4));
        Ok(ScanDuration::from_micros(
            value.clamp(minimum.as_micros(), maximum.as_micros()),
        ))
    }

    #[must_use]
    pub const fn samples(self) -> u64 {
        self.samples
    }
}
