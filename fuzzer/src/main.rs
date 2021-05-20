use std::path::PathBuf;

use libafl::{
    bolts::tuples::tuple_list,
    corpus::IndexesLenTimeMinimizerCorpusScheduler,
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
};
use log::debug;

mod qemu;

use qemu::{executor::forkserver::ForkserverExecutor, observer::SharedMemObserver};

use crate::qemu::feedback::{bitmap::MaxBitmapFeedback, bitmap_state::CoverageFeedbackState};

// we are using bit indexes so this is equivilent to 2^16 of byte sized cells
const MAP_SIZE: usize = 1 << 10;

/***
 * - [V] make sure we can catch a crash
 * - [V] print out coverage stats
 * - [ ] custom mutator
 * - [V] what is taking most time?
 * - [V] try out smaller shmem size
 *  - [ ] make qumuafl respect map size from ENV
 *  - [ ] reduce time spent on coverage stats by:
 *      - dynamic map size
 *      - using array of indexes instead of memory map
 *      - using a bit instead of byte for each memory cell
 *      - get stats on coverage cell clashes
 */

pub fn main() {
    env_logger::init();

    let stats = SimpleStats::new(|s| println!("{}", s));

    let mut mgr = SimpleEventManager::new(stats);

    /*
     * Observer - a "driver" just giving access to some resource. In our case this
     * resource is a shared memory region
     * FeedbackState -
     * Feedback - decides wether a given input is interesting
     *
     */

    // shared memory provider, it sets up the shared memory and makes sure to zero it out before
    // each target run
    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", MAP_SIZE);

    let feedback_state = CoverageFeedbackState::new("coverage", MAP_SIZE * 8);
    let feedback = MaxBitmapFeedback::new(&cov_observer);

    // let temp_corpus = OnDiskCorpus::new(PathBuf::from("./queue")).unwrap();
    let temp_corpus = InMemoryCorpus::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        temp_corpus,
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        tuple_list!(feedback_state),
    );

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let objective = CrashFeedback::new();

    // let scheduler = QueueCorpusScheduler::new();
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = ForkserverExecutor::new(
        "/fuzz/bin/harness",
        vec!["@@"],
        tuple_list!(cov_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor".into());

    let corpuses = vec![PathBuf::from("./corpus")];

    // this should run all files in corpus folder and record coverage for them
    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpuses.as_slice())
        .expect("Failed to load initial corpus");

    debug!("[+] done loading initial corpus");

    // fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzzer");

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop".into());
}
