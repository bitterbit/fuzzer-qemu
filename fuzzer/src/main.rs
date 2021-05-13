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

// TODO
// ?. observe shared memory - using StdMapObserver::new_from_ptr
// ?. run full harness in snapshots
// V update inputs between iterations
// 4. generator to use pre-made corpus using
//      state.load_initial_inputs(executor, manager,scheduler, corpus_dir)
// V. FuzzerExecutor to accept env, args and bin (should it take also shared mem? or should it
//    create it?)

pub fn main() {
    env_logger::init();

    // The Stats trait define how the fuzzer stats are reported to the user
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", MAP_SIZE);

    let covfeed_state = MapFeedbackState::with_observer(&cov_observer);
    let covfeed = MaxMapFeedback::new(&covfeed_state, &cov_observer);

    // let temp_corpus : InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
    let temp_corpus = OnDiskCorpus::new(PathBuf::from("./queue")).unwrap();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        temp_corpus,
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // Feedbacks to recognize an input as solution
        tuple_list!(covfeed_state),
    );

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let objective = CrashFeedback::new();

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();
    // let mut minimizer_sched =
    //     IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    // A fuzzer with just one stage
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
        .load_initial_inputs(
            &mut fuzzer,
            &mut executor,
            &mut mgr,
            corpuses.as_slice(),
        )
        .expect("Failed to load initial corpus");

    debug!("[+] done loading initial corpus");

    fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr).expect("Error in fuzzer");

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop".into());
}
