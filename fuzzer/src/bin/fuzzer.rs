use env_logger::Env;
use std::env;

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

use log::{debug, info};

use fuzzer::{
    config::Config,
    elf,
    executor::forkserver::ForkserverExecutor,
    feedback::{bitmap::MaxBitmapFeedback, bitmap_state::CoverageFeedbackState},
    observer::SharedMemObserver,
};

const QEMU_BASE: u64 = 0x5500000000;

/***
 * - [V] configuration and cli
 * - [V] automatic discovery of main address (convert sym to address)
 * - [ ] print out graphs exec/time and cov/time:
 *         implement an Stats object to print out stats and graphs
 * - [ ] make negative objective to hide well known crashes
 * - [ ] timer to stop fuzzing after one minute
 * - [ ] custom mutator
 * - [ ] implement multi-client main
 * - [ ] count unique objectives
 * - [ ] unique queue and crash file names
 * - [ ] retry crashes to make sure it is not a "mistake"
 * - [ ] fork afl++ to make permenent qemu patches
 * - [V] count objectives
 * - [V] make sure we can catch a crash
 * - [V] print out coverage stats
 * - [V] what is taking most time?
 *
 *
 *  Make things faster
 *  - [V] try out smaller shmem size
 *  - [ ] make qumuafl respect map size from ENV
 *  - [ ] reduce time spent on coverage stats by:
 *      - dynamic map size
 *      - using array of indexes instead of memory map
 *      - using a bit instead of byte for each memory cell
 *      - get stats on coverage cell clashes
 */

/*
 * Observer -      A "driver" just giving access to some resource. In our case this
 *                 resource is a shared memory region
 * Feedback -      Determine if a given testcase has any feedback metadata from a
 *                 testcase
 * FeedbackState - determine if feedback from a testcase is interesting. for example
 *                 if there is lot's of feedback collected but none is new we might
 *                 not be interested in this testcase
 */

fn get_args() -> Result<(String, Vec<String>), String> {
    let target: String;
    let args: Vec<String> = env::args().collect();

    if let Some(h) = args.get(1) {
        target = h.to_string();
    } else {
        return Err("Must specify target binary to be fuzzed".to_string());
    }

    let mut leftover_args = (&args[2..]).to_vec();
    if leftover_args.len() == 0 {
        leftover_args.push("@@".to_string());
    }

    debug!("args {} {:?}", &target, &leftover_args);

    return Ok((target, leftover_args.clone()));
}

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::parse("./config.ini");

    debug!("config = {:?}", config);

    let (target, args) = get_args().expect("Error while parsing arguments");

    let stats = MultiStats::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(stats);

    // shared memory provider, it sets up the shared memory and makes sure to zero it out before
    // each target run
    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", config.map_size);

    let feedback_state = CoverageFeedbackState::new("coverage", config.map_size * 8);
    let feedback = MaxBitmapFeedback::new(&cov_observer);

    let crash_corpus = OnDiskCorpus::new(config.crash_path).expect("Invalid crash directory path");

    let rand = StdRand::with_seed(current_nanos());
    let temp_corpus = OnDiskCorpus::new(
        config
            .queue_path
            .expect("In Memory Corpus not implemented. must specify path"),
    )
    .unwrap();

    let mut state = StdState::new(rand, temp_corpus, crash_corpus, tuple_list!(feedback_state));

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let objective = CrashFeedback::new();

    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let persistent_addr = Some(format!(
        "{:#x}",
        elf::find_addr_by_sym(&target, &config.persistent_sym).unwrap() + QEMU_BASE
    ));

    let mut executor = ForkserverExecutor::new(
        &config.qemu_path,
        &config.ld_library_path.unwrap_or("".to_string()),
        persistent_addr,
        &target,
        args,
        tuple_list!(cov_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor".into());

    let corpuses = vec![config.corpus_path];

    // this should run all files in corpus folder and record coverage for them
    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpuses.as_slice())
        .expect(&format!(
            "Failed to load initial corpus from {:?}",
            corpuses
        ));

    info!("[+] done loading initial corpus");

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop".into());
}