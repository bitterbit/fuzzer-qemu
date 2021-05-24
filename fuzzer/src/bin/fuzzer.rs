use configparser::ini::{Ini, IniDefault};
use env_logger::Env;
use std::{env, fs, path::PathBuf};

use libafl::{
    bolts::tuples::tuple_list,
    bolts::{current_nanos, rands::StdRand},
    corpus::IndexesLenTimeMinimizerCorpusScheduler,
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::MultiStats,
};

use log::{info, debug};

use fuzzer::feedback::{bitmap::MaxBitmapFeedback, bitmap_state::CoverageFeedbackState};
use fuzzer::{executor::forkserver::ForkserverExecutor, observer::SharedMemObserver};

const DEFAULT_MAP_SIZE: u64 = 1 << 10;

/***
 * - [ ] configuration and cli
 * - [ ] print out graphs exec/time and cov/time:
 *         implement an Stats object to print out stats and graphs
 * - [ ] make negative objective to hide well known crashes
 * - [ ] automatic discovery of main address (convert sym to address)
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

#[derive(Debug)]
struct Config {
    /// size of map used for coverage
    map_size: usize,
    /// name of "main" symbol. this will be used for qemu persistent mode
    persistent_sym: String,
    /// path to afl-qemu-trace binary
    qemu_path: String,
    /// directory in which fuzzer will store crashing testcases
    crash_path: PathBuf,
    /// directory for the initial fuzzing testcases
    corpus_path: PathBuf,
    /// directory in which fuzzer will store interesting inputs
    queue_path: Option<PathBuf>,
    /// directory to store plot data with fuzzing statistics
    plot_path: Option<String>,
}

impl Config {
    pub fn parse(path: &str) -> Self {
        let mut config = Ini::new();
        config.load(path).expect("Error while reading config file");

        let section = "general";

        let map_size = config
            .getuint(section, "map_size")
            .expect("Error parsing configuration")
            .unwrap_or(DEFAULT_MAP_SIZE) as usize;

        let persistent_sym = config
            .get(section, "map_size")
            .unwrap_or("main".to_string());

        let qemu_path = config
            .get(section, "qemu_path")
            .expect("Missing path to QEMU binary");

        let crash_path = PathBuf::from(
            config.get(section, "crash_path")
            .unwrap_or("./crashes".to_string())
        );

        let corpus_path = PathBuf::from(
            config.get(section, "corpus_path")
            .unwrap_or("./corpus".to_string())
        );

        let queue_path = if let Some(p) = config.get(section, "queue_path") {
            Some(PathBuf::from(p))
        } else {
            None
        };

        let plot_path = config.get(section, "plot_path");

        Self {
            map_size,
            persistent_sym,
            qemu_path,
            crash_path,
            corpus_path,
            queue_path,
            plot_path,
        }
    }
}

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

    return Ok((
        target,
        leftover_args.clone(),
    ));
}

pub fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::parse("./config.ini");

    debug!("config = {:?}", config);

    let (target, args) = get_args()
        .expect("Error while parsing arguments");

    let stats = MultiStats::new(|s| println!("{}", s));
    let mut mgr = SimpleEventManager::new(stats);

    // shared memory provider, it sets up the shared memory and makes sure to zero it out before
    // each target run
    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", config.map_size);

    let feedback_state = CoverageFeedbackState::new("coverage", config.map_size * 8);
    let feedback = MaxBitmapFeedback::new(&cov_observer);

    let crash_corpus = OnDiskCorpus::new(config.crash_path)
        .expect("Invalid crash directory path");

    let rand = StdRand::with_seed(current_nanos());
    let temp_corpus = OnDiskCorpus::new(config
            .queue_path
            .expect("In Memory Corpus not implemented. must specify path"))
        .unwrap();

    let mut state = StdState::new(rand, temp_corpus, crash_corpus, tuple_list!(feedback_state));

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    let objective = CrashFeedback::new();

    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = ForkserverExecutor::new(
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
        .expect(&format!("Failed to load initial corpus from {:?}", corpuses));

    info!("[+] done loading initial corpus");

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop".into());
}
