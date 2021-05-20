use libafl::{
    bolts::tuples::Named,
    feedbacks::FeedbackState,
    Error,
};

use serde::{Deserialize, Serialize};

/// Holds all coverage ever seen
/// Makes it easy to understand if we hit a new edge
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoverageFeedbackState
{
    /// Name identifier of this instance
    pub name: String,
    /// Contains information about untouched entries
    pub all_time_coverage: Vec<bool>,
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
        Ok(false)
    }
}
