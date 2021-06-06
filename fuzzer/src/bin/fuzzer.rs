use env_logger::Env;
use std::{env, fs, path::PathBuf};

use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, tuples::Named},
    corpus::IndexesLenTimeMinimizerCorpusScheduler,
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    feedback_and, feedback_or,
    feedbacks::{CrashFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::TimeObserver,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

use log::{debug, info};

use fuzzer::{
    config::Config,
    elf,
    executor::forkserver::ForkserverExecutor,
    feedback::{bitmap::MaxBitmapFeedback, bitmap_state::CoverageFeedbackState},
    observer::SharedMemObserver,
    power::PowerMutationalStage,
    stats::PlotMultiStats,
};

const COVERAGE_ID: &str = "coverage";

const QEMU_BASE: u64 = 0x5500000000;

/***
 * - [V] configuration and cli
 * - [V] automatic discovery of main address (convert sym to address)
 * - [V] print out graphs exec/time and cov/time:
 *         implement an Stats object to print out stats and graphs
 * - [ ] power schedule mutation scheduler
 * - [ ] custom mutator
 * - [ ] implement multi-client main
 * - [ ] make negative objective to hide well known crashes
 * - [ ] timer to stop fuzzing after one minute
 * - [X] count unique objectives
 * - [ ] don't save crashes that are triggered by the same path
 * - [ ] unique queue and crash file names
 * - [ ] fork afl++ to make permenent qemu patches
 * - [ ] retry crashes to make sure it is not a "mistake"
 * - [V] count objectives
 * - [V] make sure we can catch a crash
 * - [V] print out coverage stats
 * - [V] what is taking most time?
 * - [ ] try out shmem coverage list instead of const sized map
 * - [ ] plot perf (time spent in each area)
 * - [ ] pref viewer server / dashboard
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

pub fn create_dirs(config: &Config) {
    if let Some(plot) = &config.plot_path {
        // TODO don't fail if directory exists
        fs::remove_dir_all(plot).expect("Error deleting pervious plots");

        fs::create_dir_all(plot).expect("Error while creating plot directory");
    }
}

fn get_stats(config: &Config) -> PlotMultiStats {
    if let Some(plot_path) = &config.plot_path {
        PlotMultiStats::new_with_plot(PathBuf::from(plot_path), vec![COVERAGE_ID.to_string()])
    } else {
        PlotMultiStats::new()
    }
}

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let (target, args) = get_args().expect("Error while parsing arguments");
    let config = Config::parse("./config.ini");

    // find the persistent address to be looped in QEMU-AFL persistent mode
    let persistent_addr = Some(format!(
        "{:#x}",
        elf::find_addr_by_sym(&target, &config.persistent_sym).unwrap() + QEMU_BASE
    ));

    create_dirs(&config);
    debug!("config = {:?}", config);

    let rand = StdRand::with_seed(current_nanos());
    let stats = get_stats(&config);
    let mut mgr = SimpleEventManager::<BytesInput, PlotMultiStats>::new(stats);

    // shared memory provider, it sets up the shared memory and makes sure to zero it out before
    // each target run
    let coverage_observer: SharedMemObserver<u8> =
        SharedMemObserver::new(COVERAGE_ID, "__AFL_SHM_ID", config.map_size);
    let time_observer = TimeObserver::new("Time Observer");

    // feedback-state holds all-time coverage while feedback holds the last executions coverage
    // feedback will query State and ask it for it's feedback-state by name
    let feedback_state = CoverageFeedbackState::new(COVERAGE_ID, config.map_size * 8);
    let feedback = feedback_or!(
        MaxBitmapFeedback::new(COVERAGE_ID),
        TimeFeedback::new_with_observer(&time_observer)
    );

    // create another feedback-state so we don't save two crashes with the same coverage
    // but on the other hand don't discard a crash if the path was seen but didn't crash yet
    let crash_coverage_state =
        CoverageFeedbackState::new("crash_coverage_feedback_state", config.map_size * 8);
    let objective = feedback_and!(
        // Must be a crash
        CrashFeedback::new(),
        // Take it onlt if trigger new coverage over crashes
        MaxBitmapFeedback::new_with_names(
            COVERAGE_ID,
            "crash_coverage_feedback_state",
            "crash_bitmap_feedback"
        )
    );

    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    let mut stages = tuple_list!(
        // StdMutationalStage::new(StdScheduledMutator::new(havoc_mutations())),
        PowerMutationalStage::new(StdScheduledMutator::new(havoc_mutations())),
    );

    // TODO respect config
    let temp_corpus = InMemoryCorpus::new();
    let solution_corpus =
        OnDiskCorpus::new(config.crash_path).expect("Invalid crash directory path");

    let mut state = StdState::new(
        rand,
        temp_corpus,
        solution_corpus,
        tuple_list!(feedback_state, crash_coverage_state),
    );

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut executor = ForkserverExecutor::new(
        &config.qemu_path,
        &config.ld_library_path.unwrap_or("".to_string()),
        persistent_addr,
        &target,
        args,
        tuple_list!(coverage_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor".into());

    let corpuses = vec![config.corpus_path];

    // this should dry-run all files in corpus folder and record coverage+time for them
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
