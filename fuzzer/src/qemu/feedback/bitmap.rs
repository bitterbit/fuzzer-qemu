use core::marker::PhantomData;
use libafl::{
    bolts::tuples::Named,
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackStatesTuple, Reducer, MaxReducer, MapIndexesMetadata},
    inputs::Input,
    observers::{MapObserver, ObserversTuple},
    state::{HasFeedbackStates, HasMetadata},
    Error,
};

use super::bitmap_state::CoverageFeedbackState;

pub type MaxBitmapFeedback<FT, O, S> = BitmapFeedback<FT, O, MaxReducer, S>;

pub struct BitmapFeedback<FT, O, R, S>
where
    R: Reducer<u8>,
    O: MapObserver<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    /// Name identifier of the observer
    observer_name: String,
                
    // vector containing all the basic-block identifiers that we hit in this target run
    current_coverage: Vec<usize>,
    phantom: PhantomData<(FT, S, R, O)>,
}

impl<FT, O, R, S> BitmapFeedback<FT, O, R, S>
where
    R: Reducer<u8>,
    O: MapObserver<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    pub fn new(observer: &O) -> Self {
        Self {
            observer_name: observer.name().to_string(),
            current_coverage: Vec::new(),
            phantom: PhantomData,
        }
    }

    fn visit_coverage_byte(&mut self, map: &[u8], feedback_state: &mut CoverageFeedbackState, byte_index: usize) -> Result<bool, Error> {
        let mut interesting = false;

        let item = map[byte_index];
        // no coverage for this index
        if item == 0 {
            return Ok(false);
        }

        // we found coverage in this index. figure out which bit is turned on
        for bit_index in 0..8 as u8 {
            let mask: u8 = 1 << bit_index;
            let positive = item & mask != 0;
            let basic_block_id = byte_index*8 + bit_index as usize;

            if positive {
                self.current_coverage.push(basic_block_id);
                let seen_before = feedback_state.check_if_seen_and_mark(basic_block_id)?;  
                if seen_before == false {
                    interesting = true;
                }
            }
        }

        Ok(interesting)
    }
}

impl<I, FT, O, R, S> Feedback<I, S> for BitmapFeedback<FT, O, R, S>
where
    R: Reducer<u8>,
    O: MapObserver<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
    I: Input,
{
    fn is_interesting<OT>(
        &mut self,
        state: &mut S,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        OT: ObserversTuple,
    {
        let mut interesting = false;
        let observer = observers.match_name::<O>(&self.observer_name).unwrap();
        let size = observer.usable_count();

        let mut map_state: &mut CoverageFeedbackState = state
            .feedback_states_mut()
            .match_name_mut::<CoverageFeedbackState>(&self.observer_name.to_string())
            .unwrap();

        for i in 0..size {
            if self.visit_coverage_byte(observer.map(), &mut map_state, i)? {
                interesting = true;
            }
        }

        Ok(interesting)
    }

    fn append_metadata(&mut self, _state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        let meta = MapIndexesMetadata::new(core::mem::take(&mut self.current_coverage));
        testcase.add_metadata(meta);

        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.current_coverage.clear();
        Ok(())
    }
}

impl<FT, O, R, S> Named for BitmapFeedback<FT, O, R, S>
where
    R: Reducer<u8>,
    O: MapObserver<u8>,
    S: HasFeedbackStates<FT>,
    FT: FeedbackStatesTuple,
{
    #[inline]
    fn name(&self) -> &str {
        "BitmapFeedback"
    }
}
