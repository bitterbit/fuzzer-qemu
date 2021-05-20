use libafl::{bolts::tuples::tuple_list, observers::MapObserver, executors::ExitKind};

mod qemu;
use crate::qemu::{
    observer::SharedMemObserver,
    executor::simple::SimpleQEMU,
};

use std::env;

use log::{debug, info, warn};
use env_logger::Env;

const MAP_SIZE: usize = 1 << 10;

pub fn main() {
    env_logger::from_env(Env::default().default_filter_or("info")).init();

    if let Some((target, args)) = parse_args() {
        run(target, args);
        return;
    }

    warn!("Usage: target [args]...");
}

fn parse_args() -> Option<(String, Vec<String>)> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        return None;
    }

    let target = args[1].to_string();
    let leftover_args = &args[2..];

    Some((target, leftover_args.to_vec()))
}

fn collect_bit_coverage(map: &[u8]) -> Vec<usize> {
    let mut coverage: Vec<usize> = Vec::new();

    // for each byte
    for i in 0..map.len() {
        let val = map[i];
        if  val != 0 {
            // if not zero, check which bit is turned on
            for bit in 0..8 as u8 {
                let mask = 1 << bit;
                debug!("mask 1<<{} = {}", bit, mask);
                if val & mask != 0 {
                    let key = i*8 + (bit as usize);
                    coverage.push(key);
                }
            }

        }
    }

    return coverage;
}

fn collect_byte_coverage(map: &[u8]) -> Vec<usize> {
    let mut coverage: Vec<usize> = Vec::new();

    for i in 0..map.len() {
        if map[i] != 0 {
            coverage.push(i);
        }
    }

    return coverage;
}

fn run(target: String, args: Vec<String>) {
    let cov_observer: SharedMemObserver<u8> =
        SharedMemObserver::new("coverage", "__AFL_SHM_ID", MAP_SIZE);

    debug!("QEMU target={} args={:?}", target, args);

    let qemu = SimpleQEMU::new(
        target,
        args.to_vec(),
    );

    let exit_kind = qemu.sync_run();

    let coverage = collect_bit_coverage(cov_observer.map());
    // let coverage = collect_byte_coverage(cov_observer.map());

    debug!("coverage {:?}", coverage);
    info!("done! coverage={} exit={:?}", coverage.len(), exit_kind);
}

