use libafl::{
    bolts::tuples::Named,
    feedbacks::FeedbackState,
    Error,
};

use serde::{Deserialize, Serialize};
use log::debug;

/// Holds all coverage ever seen
/// Makes it easy to understand if we hit a new edge
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoverageFeedbackState
{
    /// Name identifier of this instance
    pub name: String,
    /// Contains information about untouched entries
    all_time_coverage: Vec<bool>,
    count: u64,
}

impl FeedbackState for CoverageFeedbackState {}

impl Named for CoverageFeedbackState {
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl CoverageFeedbackState {
    /// Create new `MapFeedbackState`
    #[must_use]
    pub fn new(name: &'static str, map_size: usize) -> Self {
        Self {
            name: name.to_string(),
            all_time_coverage: vec![false; map_size],
            count: 0,
        }
    }

    pub fn check_if_seen_and_mark(&mut self, index: usize) -> Result<bool, Error> {
        if index >= self.all_time_coverage.len() {
            return Err(Error::IllegalArgument("index is too big for coverage array".to_string()))
        }

        if self.all_time_coverage[index] {
            return Ok(true);
        }

        // we have never seen it up until now,
        // mark it as seen and return false to show it was not seen
        self.all_time_coverage[index] = true;
        self.count += 1;
        debug!("new coverage: #edge {}", self.count);

        Ok(false)
    }

    pub fn get_all_time_count(&self) -> u64 {
        self.count
    }
}
