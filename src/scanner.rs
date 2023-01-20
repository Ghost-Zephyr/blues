use std::{
    collections::HashMap,
    sync::{mpsc, Mutex, Arc},
    time::{Duration, Instant},
    net::{Ipv4Addr, IpAddr},
    thread::sleep, //io,
    vec::Vec};

use serde::{Deserialize, Serialize};
use log::{trace, debug, info, error};
use icmp::IcmpSocket;
use tokio::{task, };

use crate::{
    RESPONSE_SIZE,
    ICMP_PACKET, PACKET_SIZE, SIZE,
    IPStore, checksum, connect,
    rand_ip};

static PROBE: [u8; SIZE] = [0x66; SIZE];

#[derive(Clone)]
pub struct Scanner {
    timings: Arc<Mutex<HashMap<Ipv4Addr, Instant>>>,
//    scanned: Arc<Mutex<Vec<Ipv4Addr>>>,
    pub dsts: Vec<Destination>,
    pub dead: Vec<Ipv4Addr>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Destination {
    pub round_trip: Duration,
    pub small: bool,
    pub ip: Ipv4Addr,
}

struct PingResponse {
    pub finish: Instant,
//    pub data: Vec<u8>,
    pub corrupt: bool,
    pub ip: Ipv4Addr,
    pub small: bool,
}

//pub type PingResult = Result<PingResponse, io::Error>;
pub type ScanResult = Result<Destination, Ipv4Addr>;

impl Scanner {
    pub fn new() -> Self {
        debug!("Initializing a blues::Scanner");
        Self {
            timings: Arc::new(Mutex::new(HashMap::new())),
            dsts: vec![], dead: vec![]
        }
    }

    pub fn load(file: &str) -> Self {
        let mut scanner = Self::new();
        let store = IPStore::load(file);
        scanner.dsts = store.dsts;
        scanner.dead = store.dead;
        scanner
    }

    #[inline]
    fn next_ip(&mut self) -> Ipv4Addr {
        let mut ip = rand_ip();
//        let mut ip = Ipv4Addr::new(192, 168, 88, 1);
        while self.scanned(&ip) {
            ip = rand_ip(); }
        ip
    }

    #[inline]
    fn scanned(&self, ip: &Ipv4Addr) -> bool {
         for scanned in self.timings.lock().unwrap().keys() {
            if *ip == *scanned { return true; }
        }
        false
    }

    pub async fn mass_scan(&mut self, throttle: usize, parallel: usize, limit: usize, rand: bool) {
        let (tx, rx) = mpsc::channel();
        let listner = task::spawn(listner(rx));
        info!("Starting mass scan with a limit of {} and {} to randomized IP order!", limit, rand);
        let duration = Duration::from_millis(throttle as u64);
        let mut futs: Vec<task::JoinHandle<()>> = vec![];

        for _ in 0..limit {
            if futs.len() >= parallel {
                pop_futs(&mut futs).await;
            }
            let ip = self.next_ip();
            futs.push(task::spawn(ping(ip, &PROBE)));
            self.timings.lock().unwrap().insert(ip, Instant::now());
            sleep(duration);
        }
        info!("Done pinging");
        while !futs.is_empty() { pop_futs(&mut futs).await; }
        if let Err(err) = tx.send(()) {
            trace!("Error sending exit signal to the listner thread: {err:#?}");
        };
        drop(tx);
        let pings = listner.await.unwrap();
        info!("Handling responeses");
        for ping in pings {
            if ping.corrupt || ping.small {
                self.dead.push(ping.ip);
            }
            let timings = self.timings.lock().unwrap();
            let start = match timings.get(&ping.ip) {
                None => {
                    error!("No timing found for IP: {}, assuming it's dead!", ping.ip);
                    self.dead.push(ping.ip);
                    continue
                },
                Some(start) => *start,
            };
            self.dsts.push(Destination {
                round_trip: ping.finish.duration_since(start),
                small: ping.small, ip: ping.ip
            });
        }
    }
}

async fn pop_futs(futs: &mut Vec<task::JoinHandle<()>>) {
    futs.pop().expect("Unable to pop of futures vec during mass_scan()!").await.unwrap();
}

async fn ping(ip: Ipv4Addr, data: &[u8]) {
    trace!("Scanning IP \"{ip}\"");
    let mut pack = ICMP_PACKET.to_vec();

    pack[4..8].copy_from_slice(&ip.octets());
    pack.append(&mut data.to_vec());

    let checksum = checksum(&pack);
    pack[2] = checksum[0];
    pack[3] = checksum[1];

    let mut socket = connect(IpAddr::V4(ip));

    match socket.send(&pack) {
        Ok(size) => if size != pack.len() { debug!("Sent {size} bytes of {} bytes to {ip}", pack.len()) },
        Err(err) => debug!("Unable to ping IP {ip}: {err:?}"),
    }
    debug!("Ping packet sent to IP \"{ip}\"");
}

async fn listner(chan: mpsc::Receiver<()>) -> Vec<PingResponse> {
    let socket = match IcmpSocket::connect(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))) {
        Err(err) => panic!("Unable to open listening socket: {err:?}"),
        Ok(sock) => sock,
    };
    socket.set_read_timeout(Some(Duration::from_secs(1)));
    let mut handles = vec![];
    info!("Listner started");
    loop {
        let mut response: [u8; RESPONSE_SIZE] = [0; RESPONSE_SIZE];
        match socket.recv(&mut response) {
            Ok(size) => handles.push(task::spawn(handler(response, size))),
            Err(err) => trace!("Error reading a ping reply: {err:?}"),
        }
        match chan.try_recv() {
            Err(err) => match err {
                mpsc::TryRecvError::Disconnected => {
                    error!("Listner threads message queue is disconnected!");
                    break
                },
                mpsc::TryRecvError::Empty => (),
            }
            Ok(_) => break,
        }
    }
    debug!("Listner stopped");
    let mut pings = vec![];
    for handle in handles {
        match handle.await {
            Err(err) => error!("Awaiting future {err:?}"),
            Ok(res) => {
                pings.push(res);
            },
        };
    }
    pings
}

async fn handler(res: [u8; RESPONSE_SIZE], size: usize) -> PingResponse {
    let data = res[28..].to_vec();
    let ip = Ipv4Addr::new(res[24], res[25], res[26], res[27]);
    info!("Handling response from \"{ip}\"");
    let mut corrupt = false;
    let small = false;
//    if size != { error!(); }
    if data != PROBE {
        // TODO small?
        corrupt = true;
    }
    PingResponse {
        finish: Instant::now(), corrupt, small, ip
        //, data
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}
