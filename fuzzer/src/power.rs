use libafl::{
    bolts::rands::Rand,
    corpus::{Corpus, Testcase},
    feedbacks::{Feedback, MapIndexesMetadata},
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    stages::Stage,
    start_timer,
    state::{HasClientPerfStats, HasCorpus, HasMetadata, HasRand},
    Error, Evaluator, HasFeedback,
};

#[cfg(feature = "introspection")]
use libafl::stats::PerfFeature;

use log::debug;
use log::warn;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::Hasher;
use std::marker::PhantomData;
use std::ops::Div;
use std::ops::Mul;
use std::time::Duration;

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
    avg_map_size: usize,
    avg_exec_time: Duration,
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
            avg_map_size: 0,
            avg_exec_time: Duration::from_micros(0),
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

        let mut perf_score: f64 = 100.0;

        // the more times a path was excersized, the lower the score
        // the deeper we are into the fuzzing the higher the score
        // if a testcase is faster than normal, it's cheaper to try it
        // if a testcase has more coverage than normal it's is more probable to lead to intersting
        // mutations
        // perfer new interesting testcases to old ones as they have been less explored

        if let Some(exec_time) = case.exec_time() {
            perf_score = if exec_time.mul_f32(0.1) > self.avg_exec_time {
                10.0
            } else if exec_time.mul_f32(0.25) > self.avg_exec_time {
                25.0
            } else if exec_time.mul_f32(0.5) > self.avg_exec_time {
                50.0
            } else if exec_time.mul_f32(0.75) > self.avg_exec_time {
                75.0
            } else if exec_time.mul(4) < self.avg_exec_time {
                300.0
            } else if exec_time.mul(3) < self.avg_exec_time {
                200.0
            } else if exec_time.mul(2) < self.avg_exec_time {
                150.0
            } else {
                100.0
            };
        }

        let map_size = meta.list.len() as f64;
        let avg_map_size = self.avg_map_size as f64;

        perf_score = if map_size * 0.3 > avg_map_size {
            perf_score * 3.0
        } else if map_size * 0.5 > avg_map_size {
            perf_score * 2.0
        } else if map_size * 0.75 > avg_map_size {
            perf_score * 1.5
        } else if map_size * 3.0 < avg_map_size {
            perf_score * 0.25
        } else if map_size * 2.0 < avg_map_size {
            perf_score * 0.5
        } else if map_size * 1.5 < avg_map_size {
            perf_score * 0.75
        } else {
            perf_score
        };

        let path_hash = self.hash_testcase(meta);
        let path_count = self.get_paths(path_hash);

        let score =
            perf_score.floor() as usize * (1 << self.fuzz_level) / (POWER_BETA * path_count);

        Ok(score)
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

    fn init_avg_stats(&mut self, state: &S) -> Result<(), Error> {
        let count = state.corpus().count();

        if count == 0 {
            return Err(Error::IllegalArgument(format!(
                "Must have at least one input in the corpus"
            )));
        }

        let mut total_exec_time = Duration::from_secs(0);
        let mut total_map_size = 0;

        for i in 0..count {
            let testcase = state.corpus().get(i)?.borrow();
            let exec_duartion = testcase
                .exec_time()
                .ok_or({ Error::KeyNotFound(format!("Testcase #{} has no exec time", i)) })?;

            total_exec_time += exec_duartion;
            // total_exec_time += exec_duartion.as_micros() as usize;

            // map size
            let meta: &MapIndexesMetadata = testcase
                .metadata()
                .get::<MapIndexesMetadata>()
                .ok_or_else(|| {
                    Error::KeyNotFound(
                        "Metadata needed for PowerMutationalStage not found in testcase"
                            .to_string(),
                    )
                })?;

            total_map_size += meta.list.len();
        }

        self.avg_exec_time = total_exec_time.div(count as u32);
        self.avg_map_size = total_map_size / count;

        Ok(())
    }
}

impl<C, E, EM, I, M, R, S, Z, F> Stage<E, EM, S, Z>
    for PowerMutationalStage<C, E, EM, I, M, R, S, Z, F>
where
    C: Corpus<I>,
    M: Mutator<I, S>,
    I: Input,
    R: Rand,
    S: HasClientPerfStats + HasCorpus<C, I> + HasRand<R>,
    Z: Evaluator<E, EM, I, S> + HasFeedback<F, I, S>,
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
        if self.avg_map_size == 0 && self.avg_exec_time.as_micros() == 0 {
            self.init_avg_stats(&state)?;
        }

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
            let (_, new_corpus_idx) =
                fuzzer.evaluate_input(state, executor, manager, input.clone())?;

            // if we got an interesting testcase, mark it's path is visited
            // otherwise mark the fathers path as visited as we probably didn't get any new
            // coverage. TODO check this last assumption
            if let Some(idx) = new_corpus_idx {
                debug!(
                    "[+] PowerMutationalStage marking path of testcase {} as visited",
                    idx
                );
                self.mark_path(&state.corpus().get(idx)?.borrow())?;
            } else {
                // create a testcase and don't save it anywhere just so we can mark it's coverage
                // as visited
                let mut testcase = Testcase::new(input.clone());
                fuzzer
                    .feedback_mut()
                    .append_metadata(state, &mut testcase)?; // add coverage to testcase
                self.mark_path(&testcase)?;
            }

            start_timer!(state);
            self.mutator.post_exec(state, i as i32, new_corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);
        }

        #[cfg(feature = "introspection")]
        state.introspection_stats_mut().finish_stage();

        self.fuzz_level += 1;

        Ok(())
    }
}
