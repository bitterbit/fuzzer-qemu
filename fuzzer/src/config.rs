use configparser::ini::Ini;
use std::path::PathBuf;

const DEFAULT_MAP_SIZE: u64 = 1 << 10;

#[derive(Debug)]
pub struct Config {
    /// size of map used for coverage
    pub map_size: usize,
    /// name of "main" symbol. this will be used for qemu persistent mode
    pub persistent_sym: String,
    /// path to afl-qemu-trace binary
    pub qemu_path: String,
    /// instruct qemu to load with libraries internaly with LD_LIBRARY_PATH
    pub ld_library_path: Option<String>,
    /// directory in which fuzzer will store crashing testcases
    pub crash_path: PathBuf,
    /// directory for the initial fuzzing testcases
    pub corpus_path: PathBuf,
    /// directory in which fuzzer will store interesting inputs
    pub queue_path: Option<PathBuf>,
    /// directory to store plot data with fuzzing statistics
    pub plot_path: Option<String>,
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
            .get(section, "persistent_sym")
            .unwrap_or("main".to_string());

        let qemu_path = config
            .get(section, "qemu_path")
            .expect("Missing path to QEMU binary");

        let crash_path = PathBuf::from(
            config
                .get(section, "crash_path")
                .unwrap_or("./crashes".to_string()),
        );

        let corpus_path = PathBuf::from(
            config
                .get(section, "corpus_path")
                .unwrap_or("./corpus".to_string()),
        );

        let queue_path = if let Some(p) = config.get(section, "queue_path") {
            Some(PathBuf::from(p))
        } else {
            None
        };

        let plot_path = config.get(section, "plot_path");
        let ld_library_path = config.get(section, "ld_library_path");

        Self {
            map_size,
            persistent_sym,
            qemu_path,
            crash_path,
            corpus_path,
            queue_path,
            plot_path,
            ld_library_path,
        }
    }
}
