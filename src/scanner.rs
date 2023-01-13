use std::{
    time::{Duration, Instant},
    net::{Ipv4Addr, IpAddr},
    thread::sleep, io,
    vec::Vec};

use serde::{Deserialize, Serialize};
use log::{trace, debug, info, error};
use icmp::IcmpSocket;
use tokio::{task, };

use crate::{
    ICMP_PACKET, PACKET_SIZE, SIZE,
    IPStore, checksum, connect,
    rand_ip};

static PROBE: [u8; SIZE] = [0x66; SIZE];

#[derive(Clone)]
pub struct Scanner {
    pub dsts: Vec<Destination>,
    pub dead: Vec<Ipv4Addr>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Destination {
    pub round_trip: usize, // Round trip in ms
    pub small: bool,
    pub ip: Ipv4Addr,
}

struct PingResponse {
    pub round_trip: usize,
    pub corrupt: bool,
    pub small: bool,
    pub data: [u8; PACKET_SIZE],
}

pub type PingResult = Result<PingResponse, io::Error>;
pub type ScanResult = Result<Destination, Ipv4Addr>;

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
    fn next_ip(&self) -> Ipv4Addr {
        let mut ip = rand_ip();
//        let mut ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 138));
        while self.scanned(&ip) {
            ip = rand_ip(); }
        ip
    }

    #[inline]
    fn scanned(&self, ip: &Ipv4Addr) -> bool {
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

    pub async fn mass_scan(&mut self, throttle: usize, parallel: usize, limit: usize, rand: bool) {
        info!("Starting mass scan with a limit of {} and {} to randomized IP order!", limit, rand);
        let duration = Duration::from_millis(throttle as u64);
        let mut futs: Vec<task::JoinHandle<()>> = vec![];
        let listner = task::spawn(listner());

        for _i in 0..limit {
            if futs.len() >= parallel {
                pop_futs(&mut futs).await;
            }
            futs.push(task::spawn(ping(self.next_ip(), &PROBE)));
            sleep(duration);
        }
        while !futs.is_empty() { pop_futs(&mut futs).await; }
        listner.abort();
    }
}

async fn pop_futs(futs: &mut Vec<task::JoinHandle<()>>) {
    futs.pop().expect("Unable to pop of futures vec during mass_scan()!").await;
}

async fn ping(ip: Ipv4Addr, data: &[u8]) {
    trace!("Scanning IP \"{ip}\"");
    let mut pack = ICMP_PACKET.to_vec();

    pack[4..7].copy_from_slice(&ip.octets());
    pack.append(&mut data.to_vec());

    let checksum = checksum(&pack);
    pack[2] = checksum[0];
    pack[3] = checksum[1];

    let mut socket = connect(IpAddr::V4(ip));
    let start = Instant::now();

    match socket.send(&pack) {
        Ok(size) => if size != pack.len() { debug!("Sent {size} bytes of {} bytes to {ip}", pack.len()) },
        Err(err) => debug!("Unable to ping IP {ip}: {err:?}"),
    }
}

async fn listner() -> ! {
    let socket = match IcmpSocket::connect(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))) {
        Err(err) => panic!("Unable to open listening socket: {err:?}"),
        Ok(sock) => sock,
    };
    let mut handles = vec![];
    loop {
        let mut response: [u8; PACKET_SIZE] = [0; PACKET_SIZE];
        match socket.recv(&mut response) {
            Ok(size) => handles.push(task::spawn(handler(response, size))),
            Err(err) => info!("Error reading a ping reply: {err:?}"),
        }
    }
}

async fn handler(response: [u8; PACKET_SIZE], size: usize) {
    todo!();
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
