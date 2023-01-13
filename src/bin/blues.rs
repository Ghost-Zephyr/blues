#[allow(clippy::upper_case_acronyms)]
use std::{
    io, net::IpAddr,
    time::Duration,
    thread::sleep};

use blues::{TIMEOUT, PingStore, IPStore, Scanner, get_rt};
use clap::{builder::ArgAction, Subcommand, Parser};
use nbd::server::Blocks;
use log::{trace, debug, info, error};

/// Blues "cloud" storage engine
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Max worker threads to use for multi threaded operations
    #[arg(short, long, value_parser, default_value_t = num_cpus::get())]
    threads: usize,

    /// Save file to store ping destinations
    #[arg(short, long, value_parser, default_value = "ips.json")]
    file: String,

    /// Subcommands
    #[command(subcommand)]
    sub: Command,
}

/// Subcommands (enum)
#[derive(Subcommand, Debug)]
#[command()]
enum Command {
    /// Scan the internet to find optimal destinations
    Recon {
        /// Please be a good netizen, how many ms beetween ping bursts
        #[arg(short, long, value_parser, default_value_t = 150)]
        throttle: usize,

        /// How many parallel outstanding pings to have during scanning
        #[arg(short, long, value_parser, default_value_t = 420)]
        parallel: usize,

        /// Ping timeout while scanning in ms
        #[arg(short = 'o', long, value_parser, default_value_t = 7000)]
        timeout: u64,

        /// Scan until limit is reached
        #[arg(short, long, value_parser, default_value_t = 0)]
        limit: usize,

        /// Random order of IPs
        #[arg(short, long, action = ArgAction::SetTrue)]
        rand: bool,
    },

    /// NBD server and client operations
    NBD {
        /// NBD device path
        #[arg(short, long, value_parser, default_value = "/dev/nbd0")]
        device: String,
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    info!("Starting blues");
    trace!("With args: {:#?}", args);

    match args.sub {
        Command::Recon { throttle, parallel, timeout, limit, rand } => {
            debug!("Mode is Scan/Recon");
            unsafe { TIMEOUT = Some(Duration::from_millis(timeout)) };

            let mut scanner = Scanner::load(&args.file);
            get_rt("blues Scanner worker", args.threads).block_on(
                scanner.mass_scan(throttle, parallel, limit, rand));

            info!("Saving to file: {}", args.file);
            IPStore::from_scanner(&scanner).save(&args.file);
        },

        Command::NBD { device } => {
            debug!("Mode is NBD");
            let store = PingStore::load_clients(&args.file);
            let mut data = vec![
                0x49, 0x43, 0x4d, 0x50, 0x20, 0x62, 0x61, 0x6c,
                0x6c, 0x65, 0x20, 0x6e, 0x65, 0x67, 0x65, 0x72];
//            get_rt("blues NBD driver", args.threads).spawn(store.run());
            data.append(&mut [0x66; 64].to_vec());
//            data.append(&mut [0x66; 48].to_vec());
            info!("Storing some data in a few pings!");
            store.write_at(&data, 0)?;
//            info!("Waiting for data corruption!");
//            sleep(Duration::from_millis(3000));
            let mut res: [u8; 64 + 16] = [0; 64 + 16];
//            let mut res: [u8; 64] = [0; 64];
            store.read_at(&mut res, 0)?;
            if res.to_vec() == data {
                info!("SUCCESS! Recived same data as stored!");
            } else {
                error!("Didn't recive the same data as stored!\nExpected: {data:?}\nGot: {res:?}");
            }
        }
    }
    Ok(())
}
