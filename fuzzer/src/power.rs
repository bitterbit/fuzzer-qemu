use libafl::HasFeedback;
use libafl::corpus::Testcase;
use libafl::feedbacks::MapIndexesMetadata;
use libafl::state::HasMetadata;
use libafl::{
    bolts::rands::Rand,
    corpus::Corpus,
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    stages::Stage,
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasRand},
    Error, Evaluator,
    feedbacks::Feedback,
};

use log::debug;
use log::warn;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::marker::PhantomData;

pub struct PowerMutationalStage<C, E, EM, I, M, R, S, Z, F>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>,
    F: Feedback<I, S>,
{
    mutator: M,
    /// given a path hash, how many testcases resulted in this path
    paths: HashMap<u64, usize>,
    fuzz_level: usize,
    phantom: PhantomData<(C, E, EM, I, R, S, Z, F)>,
}

const POWER_BETA: usize = 100;

type PathHash = u64;

impl<C, E, EM, I, M, R, S, Z, F> PowerMutationalStage<C, E, EM, I, M, R, S, Z, F>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S> + HasFeedback<F, I, S>,
    F: Feedback<I, S>,
{
    pub fn new(mutator: M) -> Self {
        Self {
            mutator,
            fuzz_level: 1,
            paths: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, case: &Testcase<I>) -> Result<usize, Error> {
        let meta: &MapIndexesMetadata =
            case.metadata().get::<MapIndexesMetadata>().ok_or_else(|| {
                Error::KeyNotFound(
                    "Metadata needed for PowerMutationalStage not found in testcase".to_string(),
                )
            })?;

        let mut perf_score = 100;

        // TODO calculate agains avg_map_size and avg_exec_us

        let path_hash = self.hash_testcase(meta);
        let path_count = self.get_paths(path_hash);

        // the more times a path was excersized, the lower the score
        // the deeper we are into the fuzzing the higher the score
        perf_score = perf_score * (1 << self.fuzz_level) / (POWER_BETA * path_count);

        Ok(perf_score)
    }

    /// returns the number of testcases (until now) that reached a given path
    /// @param path_hash: hash of all indexes of a given path
    fn get_paths(&self, path_hash: PathHash) -> usize {
        if let Some(count) = self.paths.get(&path_hash) {
            if *count == 0 {
                warn!("Found path hash with zero count, should be >= 1")
            }
            *count
        } else {
            1
        }
    }

    fn mark_path(&mut self, case: &Testcase<I>) -> Result<(), Error> {
        let meta: &MapIndexesMetadata =
            case.metadata().get::<MapIndexesMetadata>().ok_or_else(|| {
                Error::KeyNotFound(
                    "Metadata needed for PowerMutationalStage not found in testcase".to_string(),
                )
            })?;

        let path_hash = self.hash_testcase(meta);

        if let Some(count) = self.paths.get(&path_hash).cloned() {
            self.paths.insert(path_hash, count + 1);
        } else {
            self.paths.insert(path_hash, 1);
        }

        Ok(())
    }

    fn hash_testcase(&self, metadata: &MapIndexesMetadata) -> PathHash {
        let mut hasher = DefaultHasher::new();
        for index in metadata.list.iter() {
            hasher.write_usize(*index);
        }

        return hasher.finish();
    }
}

impl<C, E, EM, I, M, R, S, Z, F> Stage<E, EM, S, Z> for PowerMutationalStage<C, E, EM, I, M, R, S, Z, F>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S>  + HasFeedback<F, I, S>,
    F: Feedback<I, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        let num = self.iterations(&state.corpus().get(corpus_idx)?.borrow_mut())?;
        debug!(
            "[+] PowerMutationalStage decided to to mutate testcase #{} {} times",
            corpus_idx, num
        );

        for i in 0..num {
            start_timer!(state);
            let mut input = state
                .corpus()
                .get(corpus_idx)?
                .borrow_mut()
                .load_input()?
                .clone();
            mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

            start_timer!(state);
            self.mutator.mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            // Time is measured directly the `evaluate_input` function
            let (_, new_corpus_idx) = fuzzer.evaluate_input(state, executor, manager, input.clone())?;

            // if we got an interesting testcase, mark it's path is visited
            // otherwise mark the fathers path as visited as we probably didn't get any new
            // coverage. TODO check this last assumption
            if let Some(idx) = new_corpus_idx {
                debug!("[+] PowerMutationalStage marking path of testcase {} as visited", idx);
                self.mark_path(&state.corpus().get(idx)?.borrow())?;
            } else {
                // create a testcase and don't save it anywhere just so we can mark it's coverage
                // as visited
                let mut testcase = Testcase::new(input.clone());
                fuzzer.feedback_mut().append_metadata(state, &mut testcase)?;
                self.mark_path(&testcase)?;
            }

            start_timer!(state);
            self.mutator.post_exec(state, i as i32, new_corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        self.fuzz_level += 1;

        Ok(())
    }
}

// // only splice and byte flips
// pub fn default_power_mutations<C, I, R, S>() -> tuple_list_type!(
//        BitFlipMutator<I, R, S>,
//        ByteFlipMutator<I, R, S>,
//        ByteIncMutator<I, R, S>,
//        ByteDecMutator<I, R, S>,
//        ByteNegMutator<I, R, S>,
//        ByteRandMutator<I, R, S>,
//        ByteAddMutator<I, R, S>,
//        WordAddMutator<I, R, S>,
//        DwordAddMutator<I, R, S>,
//        QwordAddMutator<I, R, S>,
//        ByteInterestingMutator<I, R, S>,
//        WordInterestingMutator<I, R, S>,
//        DwordInterestingMutator<I, R, S>,
//        BytesDeleteMutator<I, R, S>,
//        BytesDeleteMutator<I, R, S>,
//        BytesDeleteMutator<I, R, S>,
//        BytesDeleteMutator<I, R, S>,
//        BytesExpandMutator<I, R, S>,
//        BytesInsertMutator<I, R, S>,
//        BytesRandInsertMutator<I, R, S>,
//        BytesSetMutator<I, R, S>,
//        BytesRandSetMutator<I, R, S>,
//        BytesCopyMutator<I, R, S>,
//        BytesSwapMutator<I, R, S>,
//        CrossoverInsertMutator<C, I, R, S>,
//        CrossoverReplaceMutator<C, I, R, S>,
//    )
// where
//     I: Input + HasBytesVec,
//     S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
//     C: Corpus<I>,
//     R: Rand,
// {
//     tuple_list!(
//         BitFlipMutator::new(),
//         ByteFlipMutator::new(),
//         ByteIncMutator::new(),
//         ByteDecMutator::new(),
//         ByteNegMutator::new(),
//         ByteRandMutator::new(),
//         ByteAddMutator::new(),
//         WordAddMutator::new(),
//         DwordAddMutator::new(),
//         QwordAddMutator::new(),
//         ByteInterestingMutator::new(),
//         WordInterestingMutator::new(),
//         DwordInterestingMutator::new(),
//         BytesDeleteMutator::new(),
//         BytesDeleteMutator::new(),
//         BytesDeleteMutator::new(),
//         BytesDeleteMutator::new(),
//         BytesExpandMutator::new(),
//         BytesInsertMutator::new(),
//         BytesRandInsertMutator::new(),
//         BytesSetMutator::new(),
//         BytesRandSetMutator::new(),
//         BytesCopyMutator::new(),
//         BytesSwapMutator::new(),
//         CrossoverInsertMutator::new(),
//         CrossoverReplaceMutator::new(),
//     )
// }
