use std::{
    vec::Vec, net::{Ipv4Addr, IpAddr},
    time::Duration, thread::sleep};

use serde::{Deserialize, Serialize};
use log::{trace, debug, info, error};
use tokio::task;

use crate::{
    pinger::rand_ip,
    IPStore, Pinger};

//static PROBE_CHK: [u8; 2] = [0x51, 0x59];
static PROBE: [u8; 64] = [0x66; 64];

#[derive(Clone)]
pub struct Scanner {
    pub dsts: Vec<Destination>,
    pub dead: Vec<IpAddr>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Destination {
    pub round_trip: usize, // Round trip in ms
    pub small: bool,
    pub ip: IpAddr,
}

pub type ScanResult = Result<Destination, IpAddr>;

impl Scanner {
    pub fn new() -> Self {
        debug!("Initializing a blues::Scanner");
        Self { dsts: vec![], dead: vec![] }
    }

    pub fn load(file: &str) -> Self {
        let mut scanner = Self::new();
        let store = IPStore::load(file);
        scanner.dsts = store.dsts;
        scanner.dead = store.dead;
        scanner
    }

    #[inline]
    fn next_ip(&self) -> IpAddr {
//        let mut ip = rand_ip();
        let mut ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 138));
        while self.scanned(&ip) {
            ip = rand_ip(); }
        ip
    }

    #[inline]
    fn scanned(&self, ip: &IpAddr) -> bool {
        for dead in &self.dead {
            if ip == dead { return true; }
        }
        for dst in &self.dsts {
            if ip == &dst.ip {
                return true;
            }
        }
        false
    }

    async fn pop_futs(&mut self, futs: &mut Vec<task::JoinHandle<ScanResult>>) {
        let fut = futs.pop().expect("Unable to pop of futures vec during mass_scan()!");
        match fut.await {
           Err(err) => {
               error!("Joing future: {:?}", err);
           },
           Ok(res) => match res {
               Ok(dst) => self.dsts.push(dst),
               Err(ip) => self.dead.push(ip),
           }
        }
    }

    pub async fn mass_scan(&mut self, throttle: usize, parallel: usize, limit: usize, rand: bool) {
        info!("Starting mass scan with a limit of {} and {} to randomized IP order!", limit, rand);
        let duration = Duration::from_millis(throttle as u64);
        let mut futs: Vec<task::JoinHandle<ScanResult>> = vec![];

        for _i in 0..limit {
            if futs.len() >= parallel {
                self.pop_futs(&mut futs).await;
            }
            futs.push(task::spawn(scan(self.next_ip())));
            sleep(duration);
        }
        while !futs.is_empty() {
            self.pop_futs(&mut futs).await }
    }
}

pub async fn scan(ip: IpAddr) -> Result<Destination, IpAddr> {
    trace!("Scanning IP \"{}\"", ip);
    if let Ok(res) = Pinger::new().data(PROBE).ping(ip) {
        info!("Good result scanning IP \"{}\": {}ms", ip, res.round_trip);
        if res.corrupt { return Err(ip) }
        Ok(Destination { ip, small: res.small, round_trip: res.round_trip })
    } else { Err(ip) }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
