use libafl::{
    bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider},
    corpus::IndexesLenTimeMinimizerCorpusScheduler,
    feedbacks::{MapFeedback, MaxReducer, TimeFeedback, TimeoutFeedback},
    utils::RomuTrioRand,
};
use std::path::PathBuf;

use libafl::{
    bolts::tuples::tuple_list,
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::TimeObserver,
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
};
use log::debug;

mod qemu;

use qemu::{forkserver::ForkserverExecutor, observer::SharedMemObserver};

const MAP_SIZE: usize = 1 << 16;

pub fn main() {
    env_logger::init();

    let stats = SimpleStats::new(|s| println!("{}", s));

    let mut mgr = SimpleEventManager::new(stats);

    // shared memory provider, it sets up the shared memory and makes sure to zero it out before
    // each target run
    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", MAP_SIZE);

    let covfeed_state = MapFeedbackState::with_observer(&cov_observer);
    let covfeed = MaxMapFeedback::new(&covfeed_state, &cov_observer);

    let temp_corpus = OnDiskCorpus::new(PathBuf::from("./queue")).unwrap();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        temp_corpus,
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        tuple_list!(covfeed_state),
    );

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let objective = CrashFeedback::new();

    let scheduler = QueueCorpusScheduler::new();
    // let mut minimizer_sched =
    //     IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, covfeed, objective);

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
