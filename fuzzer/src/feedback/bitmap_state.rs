use std::{collections::{HashMap, hash_map::DefaultHasher}, hash::Hasher};

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
    path_hit_count: HashMap<u64, usize>,
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
            path_hit_count: HashMap::new(),
            count: 0,
        }
    }

    fn seen_edge(&self, edge: usize) -> Result<bool, Error> {
        if edge >= self.all_time_coverage.len() {
            return Err(Error::IllegalArgument("edge index is too big for coverage array".to_string()))
        }

        Ok(self.all_time_coverage[edge])
    }

    pub fn is_path_interesting(&self, path: &[usize]) -> Result<bool, Error> {
        for edge in path.iter() {
            let seen_edge = self.seen_edge(*edge)?;

            if seen_edge == false {
                return Ok(true)
            }
        }

        Ok(false)
    }

    /// returns true if increased all-time count, false if no change
    pub fn mark_path(&mut self, path: &[usize]) -> Result<(), Error> {
        for edge in path {
            if self.all_time_coverage[*edge] == false {
                self.count += 1;
                debug!("new coverage: #edge {}", self.count);
            }

            self.all_time_coverage[*edge] = true;
        }

        Ok(())
    }

    pub fn get_all_time_count(&self) -> u64 {
        self.count
    }
}
