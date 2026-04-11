use lb_types::HealthStatus;

/// Tracks health state transitions for a single backend.
#[derive(Debug, Clone)]
pub struct HealthState {
    pub status: HealthStatus,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
}

impl HealthState {
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Unknown,
            consecutive_successes: 0,
            consecutive_failures: 0,
        }
    }

    /// Record a probe result. Returns `Some(new_status)` on state transition.
    pub fn record_result(
        &mut self,
        success: bool,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
    ) -> Option<HealthStatus> {
        if success {
            self.consecutive_successes += 1;
            self.consecutive_failures = 0;
        } else {
            self.consecutive_failures += 1;
            self.consecutive_successes = 0;
        }

        match self.status {
            HealthStatus::Unknown => {
                if self.consecutive_successes >= healthy_threshold {
                    self.status = HealthStatus::Healthy;
                    Some(HealthStatus::Healthy)
                } else if self.consecutive_failures >= unhealthy_threshold {
                    self.status = HealthStatus::Unhealthy;
                    Some(HealthStatus::Unhealthy)
                } else {
                    None
                }
            }
            HealthStatus::Healthy => {
                if self.consecutive_failures >= unhealthy_threshold {
                    self.status = HealthStatus::Unhealthy;
                    Some(HealthStatus::Unhealthy)
                } else {
                    None
                }
            }
            HealthStatus::Unhealthy => {
                if self.consecutive_successes >= healthy_threshold {
                    self.status = HealthStatus::Healthy;
                    Some(HealthStatus::Healthy)
                } else {
                    None
                }
            }
        }
    }
}

impl Default for HealthState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_to_healthy() {
        let mut state = HealthState::new();
        assert_eq!(state.record_result(true, 2, 3), None);
        assert_eq!(state.record_result(true, 2, 3), Some(HealthStatus::Healthy));
        assert_eq!(state.status, HealthStatus::Healthy);
    }

    #[test]
    fn unknown_to_unhealthy() {
        let mut state = HealthState::new();
        assert_eq!(state.record_result(false, 2, 3), None);
        assert_eq!(state.record_result(false, 2, 3), None);
        assert_eq!(
            state.record_result(false, 2, 3),
            Some(HealthStatus::Unhealthy)
        );
    }

    #[test]
    fn healthy_to_unhealthy() {
        let mut state = HealthState::new();
        state.record_result(true, 2, 3);
        state.record_result(true, 2, 3);
        assert_eq!(state.status, HealthStatus::Healthy);

        assert_eq!(state.record_result(false, 2, 3), None);
        assert_eq!(state.record_result(false, 2, 3), None);
        assert_eq!(
            state.record_result(false, 2, 3),
            Some(HealthStatus::Unhealthy)
        );
    }

    #[test]
    fn unhealthy_to_healthy() {
        let mut state = HealthState::new();
        // Get to unhealthy
        for _ in 0..3 {
            state.record_result(false, 2, 3);
        }
        assert_eq!(state.status, HealthStatus::Unhealthy);

        assert_eq!(state.record_result(true, 2, 3), None);
        assert_eq!(state.record_result(true, 2, 3), Some(HealthStatus::Healthy));
    }

    #[test]
    fn mixed_results_no_transition() {
        let mut state = HealthState::new();
        // Alternate success/failure: never reaches threshold
        for _ in 0..10 {
            assert_eq!(state.record_result(true, 3, 3), None);
            assert_eq!(state.record_result(false, 3, 3), None);
        }
        assert_eq!(state.status, HealthStatus::Unknown);
    }

    #[test]
    fn failure_resets_success_counter() {
        let mut state = HealthState::new();
        state.record_result(true, 3, 3);
        state.record_result(true, 3, 3);
        // One failure resets
        state.record_result(false, 3, 3);
        assert_eq!(state.consecutive_successes, 0);
        assert_eq!(state.consecutive_failures, 1);
    }
}
