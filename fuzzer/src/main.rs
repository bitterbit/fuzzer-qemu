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
    feedbacks::{CrashFeedback, FeedbacksTuple, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::TimeObserver,
    stages::mutational::StdMutationalStage,
    state::State,
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

    let coverage_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", MAP_SIZE);

    let coverage_feedback =
        MaxMapFeedback::new_with_observer_track(&coverage_observer, true, false);

    // let temp_corpus : InMemoryCorpus<BytesInput> = InMemoryCorpus::new();
    let temp_corpus = OnDiskCorpus::new(PathBuf::from("./queue")).unwrap();

    // create a State from scratch
    let mut state = State::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        temp_corpus,
        // Feedbacks to rate the interestingness of an input
        tuple_list!(coverage_feedback),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // Feedbacks to recognize an input as solution
        tuple_list!(CrashFeedback::new()),
    );

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // A queue policy to get testcasess from the corpus
    // let scheduler = QueueCorpusScheduler::new();
    let minimizer_sched = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut executor = ForkserverExecutor::new(
        "/fuzz/bin/harness",
        vec!["@@"],
        tuple_list!(coverage_observer),
    )
    .expect("Failed to create the Executor".into());

    let corpuses = vec![PathBuf::from("./corpus")];

    // this should run all files in corpus folder and record coverage for them
    state
        .load_initial_inputs(
            &mut executor,
            &mut mgr,
            &minimizer_sched,
            corpuses.as_slice(),
        )
        .expect("Failed to load initial corpus");

    debug!("[+] done loading initial corpus");

    // let testcase = temp_corpus.get(0);
    //
    // scheduler ->
    //  executor

    // fuzzer.fuzz_one(&mut state, &mut executor, &mut mgr, &scheduler)
    //     .expect("Error running fuzzer once");

    fuzzer
        .fuzz_loop(&mut state, &mut executor, &mut mgr, &minimizer_sched)
        .expect("Error in the fuzzing loop".into());
}
