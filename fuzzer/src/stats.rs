use libafl::{
    bolts::current_time,
    stats::{ClientStats, MultiStats, Stats, UserStats},
};
use log::debug;
use std::{io::Write, time::Duration};
use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
    time,
};

pub struct PlotMultiStats {
    stats: MultiStats<fn(String)>,
    plot_file: Option<File>,
    last_write: Duration,
    user_stats: Vec<String>, // list of user stats we should track
}

impl PlotMultiStats
{
    pub fn new() -> Self {
        let printer = |s| println!("{}", s);
        Self {
            stats: MultiStats::new(printer),
            plot_file: None,
            last_write: current_time(),
            user_stats: Vec::new(),
        }
    }

    pub fn new_with_plot(plot_dir: PathBuf, user_stats: Vec<String>) -> Self {
        let printer = |s| println!("{}", s);
        let plot_f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(plot_dir.join("global.dat"))
            .expect("Error creating new plot file");

        let plot_file = Some(plot_f);

        Self {
            stats: MultiStats::new(printer),
            plot_file,
            last_write: current_time(),
            user_stats,
        }
    }

    fn write_global_plot(&mut self) -> Result<(), std::io::Error> {
        if self.plot_file.is_none() {
            return Ok(());
        }

        self.write_header_if_needed()?;

        let cur_time = current_time();
        if (cur_time - self.last_write).as_secs() < 1 {
            return Ok(());
        }

        let total_execs = self.stats.total_execs();
        let exec_sec = self.stats.execs_per_sec();
        let corpus_size = self.stats.corpus_size();
        let objective_size = self.stats.objective_size();
        let extra = self.get_user_stats();


        let mut f = self.plot_file.as_ref().unwrap();

        // time, total_execs, exec/sec, corpus_size, coverage, crashes
        writeln!(f, "{} {} {} {} {} {}", 
            cur_time.as_secs(), // time since unix epoch
            total_execs,
            exec_sec,
            corpus_size,
            objective_size, 
            extra)?;

        self.last_write = cur_time;

        debug!("writing line to stats file {:?}", f);

        return Ok(());
    }

    fn get_extra_user_stat_names(&self, sep: &str) -> String {
        let mut names = String::new();
        for extra_stat_name in self.user_stats.iter() {
            names += &format!("{}{}", sep, extra_stat_name);
        }

        names
    }

    fn write_header_if_needed(&self) -> Result<(), std::io::Error> {

        if self.plot_file.is_none() {
            return Ok(());
        }

        let mut f = self.plot_file.as_ref().unwrap();
       
        // check if header is needed
        let meta = f.metadata()?;
        if meta.len() != 0 { 
            return Ok(());
        }

        let header = "time, total_execs, exec/sec, corpus_size, crashes".to_string(); 
        let extra_header = self.get_extra_user_stat_names(", ");
        writeln!(f, "{}{}", header, extra_header).unwrap();

        Ok(())
    }

    fn get_user_stats(&mut self) -> String {
        let mut s = String::new();

        for stat_name in self.user_stats.clone() {
            if let Some(val) = self.get_user_stat(&stat_name) {
                s += &format!(" {}", val);
            }
        }

        return s.to_string();
    }

    fn get_user_stat(&mut self, stat_name: &str) -> Option<u64> {
        let mut max_value = None;
        for client_stats in self.stats.client_stats_mut().iter_mut() {
            if let Some(stat) = client_stats.get_user_stats(stat_name) {
                if let Some(value) = stat.to_num() {

                    if max_value.is_none() { 
                        max_value = Some(0);
                    }

                    max_value = Some(std::cmp::max(max_value.unwrap(), value));
                }
            }
        }

        return max_value;
    }

}

trait UserStatsInto {
    fn to_num(&self) -> Option<u64>;
}

impl UserStatsInto for UserStats {
    fn to_num(&self) -> Option<u64> {
        match self {
            UserStats::Number(n) => Some(*n),
            UserStats::String(_s) => None,
            UserStats::Ratio(a, _b) => Some(*a),
        }
    }
}

impl Stats for PlotMultiStats
{
    /// the client stats, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.stats.client_stats_mut()
    }

    /// the client stats
    fn client_stats(&self) -> &[ClientStats] {
        self.stats.client_stats()
    }

    /// Time this fuzzing run stated
    fn start_time(&mut self) -> time::Duration {
        self.stats.start_time()
    }

    fn display(&mut self, event_msg: String, sender_id: u32) {
        self.write_global_plot()
            .expect("Error while writing plot data");
        self.stats.display(event_msg, sender_id)
    }
}
