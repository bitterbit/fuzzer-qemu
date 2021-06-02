use core::marker::PhantomData;
use libafl::{
    bolts::tuples::Named,
    corpus::Testcase,
    events::{Event, EventFirer},
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackStatesTuple, MapIndexesMetadata, MaxReducer, Reducer},
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    state::{HasFeedbackStates, HasMetadata},
    stats::UserStats,
    Error,
};
use std::{collections::hash_map::DefaultHasher, hash::Hasher};

use crate::observer::SharedMemObserver;

use super::bitmap_state::CoverageFeedbackState;

pub type MaxBitmapFeedback<FT, S> = BitmapFeedback<FT, MaxReducer, S>;

use log::{debug, trace};

pub struct BitmapFeedback<FT, R, S>
where
    R: Reducer<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    /// Name of this feedback, used in fired events
    name: String,
    /// Name identifier of the observer
    observer_name: String,
    /// Name identifier of the shared feedback state
    feedback_state_name: String,

    // vector containing all the basic-block identifiers that we hit in this target run
    current_coverage: Vec<usize>,
    current_path_hash: u64,
    phantom: PhantomData<(FT, S, R)>,
}

impl<FT, R, S> BitmapFeedback<FT, R, S>
where
    R: Reducer<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            observer_name: name.to_string(),
            feedback_state_name: name.to_string(),
            current_coverage: Vec::new(),
            current_path_hash: 0,
            phantom: PhantomData,
        }
    }

    pub fn new_with_names(observer_name: &str, feedback_state_name: &str, name: &str) -> Self {
        Self {
            name: name.to_string(),
            observer_name: observer_name.to_string(),
            feedback_state_name: feedback_state_name.to_string(),
            current_coverage: Vec::new(),
            current_path_hash: 0,
            phantom: PhantomData,
        }
    }

    /// check if the map in the given index has any coverage information
    /// if so add it to `self.current_coverage`
    fn visit_coverage_byte(&mut self, map: &[u8], byte_index: usize) {
        let item = map[byte_index];
        // no coverage for this index
        if item == 0 {
            return;
        }

        // we found coverage in this index. figure out which bit is turned on
        for bit_index in 0..8 as u8 {
            let mask: u8 = 1 << bit_index;
            let empty = (item & mask) == 0;
            let basic_block_id = byte_index * 8 + bit_index as usize;

            if !empty {
                trace!("push coverage id {}", basic_block_id);
                self.current_coverage.push(basic_block_id);
            }
        }
    }

    /// hash the path stored in `self.current_coverage` and store it in `self.current_path_hash`
    fn calculate_path_hash(&mut self) {
        let mut hasher = DefaultHasher::new();
        for edge in &self.current_coverage {
            hasher.write_usize(*edge);
        }

        self.current_path_hash = hasher.finish();
    }
}

impl<I, FT, R, S> Feedback<I, S> for BitmapFeedback<FT, R, S>
where
    R: Reducer<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
    I: Input,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I, S>,
        OT: ObserversTuple,
    {
        let observer = observers.match_name::<SharedMemObserver<u8>>(&self.observer_name).unwrap();
        let size = observer.usable_count();

        let map_state: &mut CoverageFeedbackState = state
            .feedback_states_mut()
            .match_name_mut::<CoverageFeedbackState>(&self.feedback_state_name.to_string())
            .unwrap();

        for i in 0..size {
            self.visit_coverage_byte(observer.map(), i);
        }

        let interesting = map_state.is_path_interesting(&self.current_coverage)?;
        debug!("Bitmap Feedback ({}) with state({}) input interesting? {}", self.name(), map_state.name(), interesting);

        self.calculate_path_hash();

        if interesting {
            let value = UserStats::Number(map_state.get_all_time_count());

            manager.fire(
                state,
                Event::UpdateUserStats {
                    value,
                    name: self.name.to_string(),
                    phantom: PhantomData,
                },
            )?;
        }

        Ok(interesting)
    }

    fn append_metadata(&mut self, state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        // save path hash only after append_metadata is called
        // calling this before can break usage where the same bitmap is used for two or more
        // feedbacks. The first time `is_interesting` is called the testcase is interesting but by
        // the second call it will not be interesting, even though it is the exact same testcase
        let map_state: &mut CoverageFeedbackState = state
            .feedback_states_mut()
            .match_name_mut::<CoverageFeedbackState>(&self.feedback_state_name.to_string())
            .unwrap();

        map_state.mark_path(self.current_coverage.as_slice())?;

        let meta = MapIndexesMetadata::new(core::mem::take(&mut self.current_coverage));
        testcase.add_metadata(meta);
        // TODO hash current_coverage
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.current_coverage.clear();
        Ok(())
    }
}

impl<FT, R, S> Named for BitmapFeedback<FT, R, S>
where
    R: Reducer<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    #[inline]
    fn name(&self) -> &str {
        "BitmapFeedback"
    }
}
