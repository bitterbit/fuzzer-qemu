use env_logger::Env;
use std::path::PathBuf;

use libafl::{
    bolts::tuples::tuple_list,
    bolts::{current_nanos, rands::StdRand},
    corpus::IndexesLenTimeMinimizerCorpusScheduler,
    corpus::{OnDiskCorpus, QueueCorpusScheduler}, // InMemoryCorpus
    events::SimpleEventManager,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::MultiStats,
};

use log::info;

use fuzzer::feedback::{bitmap::MaxBitmapFeedback, bitmap_state::CoverageFeedbackState};
use fuzzer::{executor::forkserver::ForkserverExecutor, observer::SharedMemObserver};

// we are using bit indexes so this is equivilent to 2^16 of byte sized cells
const MAP_SIZE: usize = 1 << 10;

/***
 * - [V] make sure we can catch a crash
 * - [V] print out coverage stats
 * - [V] what is taking most time?
 * - [ ] custom mutator
 * - [ ] print out graphs exec/time and cov/time: 
 *         implement an Stats object to print out stats and graphs
 * - [ ] implement multi-client main
 * - [ ] count unique objectives
 * - [V] try out smaller shmem size
 *  - [ ] make qumuafl respect map size from ENV
 *  - [ ] reduce time spent on coverage stats by:
 *      - dynamic map size
 *      - using array of indexes instead of memory map
 *      - using a bit instead of byte for each memory cell
 *      - get stats on coverage cell clashes
 */

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let stats = MultiStats::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(stats);

    /*
     * Observer -      A "driver" just giving access to some resource. In our case this
     *                 resource is a shared memory region
     * Feedback -      Determine if a given testcase has any feedback metadata from a
     *                 testcase
     * FeedbackState - determine if feedback from a testcase is interesting. for example
     *                 if there is lot's of feedback collected but none is new we might
     *                 not be interested in this testcase
     */

    // shared memory provider, it sets up the shared memory and makes sure to zero it out before
    // each target run
    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", MAP_SIZE);

    let feedback_state = CoverageFeedbackState::new("coverage", MAP_SIZE * 8);
    let feedback = MaxBitmapFeedback::new(&cov_observer);

    let temp_corpus = OnDiskCorpus::new(PathBuf::from("./queue")).unwrap();
    // let temp_corpus = InMemoryCorpus::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        temp_corpus,
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        tuple_list!(feedback_state),
    );

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let objective = CrashFeedback::new();

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

    info!("[+] done loading initial corpus");

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop".into());
}
