use std::path::PathBuf;

use libafl::{
    bolts::tuples::tuple_list,
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    observers::StdMapObserver,
    state::State,
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
};

mod pipe;
mod forkserver;

use forkserver::ForkserverExecutor;

// TODO remove
static mut SIGNALS: [u8; 16] = [0; 16];

// TODO
// 1. observe shared memory - using StdMapObserver::new_from_ptr
// 2. run full harness in snapshots
// 3. update inputs between iterations
// 4. generator to use pre-made corpus using 
//      state.load_initial_inputs(executor, manager,scheduler, corpus_dir)
// 5. FuzzerExecutor to accept env, args and bin (should it take also shared mem? or should it
//    create it?)

pub fn main() {
    // The Stats trait define how the fuzzer stats are reported to the user
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    // Create an observation channel using the siganls map
    let observer =
        StdMapObserver::new("signals", unsafe { &mut SIGNALS }, unsafe { SIGNALS.len() });

    // create a State from scratch
    let mut state = State::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Feedbacks to rate the interestingness of an input
        tuple_list!(MaxMapFeedback::new_with_observer(&observer)),
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
    let scheduler = QueueCorpusScheduler::new();

    let mut executor = ForkserverExecutor::new(
        "/fuzz/bin/harness", 
        Vec::new(), 
        tuple_list!(observer)
    ).expect("Failed to create the Executor".into());
        

    // Create the executor for an in-process function with just one observer
    // let mut executor = InProcessExecutor::new(
    //     "in-process(signals)",
    //     &mut harness,
    //     tuple_list!(observer),
    //     &mut state,
    //     &mut mgr,
    // )
    // .expect("Failed to create the Executor".into());

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut executor, &mut generator, &mut mgr, &scheduler, 8)
        .expect("Failed to generate the initial corpus".into());

    fuzzer
        .fuzz_loop(&mut state, &mut executor, &mut mgr, &scheduler)
        .expect("Error in the fuzzing loop".into());
}
