use std::{
    sync::{Mutex, Arc},
    time::Duration,
    thread::sleep,
    net::IpAddr,
    vec::Vec, io};

use log::{trace, warn, error};
use tokio::{
    sync::mpsc,
    runtime, task};
use nbd::server::Blocks;
use icmp::IcmpSocket;
use crate::{
    ICMP_PACKET, IPStore,
    pinger::connect,
    checksum,
    get_rt};

const SIZE: usize = 64; // Bits of data in each ping
static WORD_COUNT: usize = SIZE / 8; // Number of 16-bit words in each ping

type Message = (usize, usize, Vec<u8>); // Message type for the write channel

pub struct Ping {
    socks: Vec<IcmpSocket>,
    ips: Vec<IpAddr>,
    copies: usize,
}

pub struct PingStore {
    pings: Arc<Mutex<Vec<Ping>>>,
    size: u64,
}

impl PingStore {
    pub fn new() -> Self {
        Self {
            pings: Arc::new(Mutex::new(vec![])),
            size: 0,
        }
    }

    pub fn load_clients(file: &str) -> Self {
        let ips = IPStore::load(file);
        let mut store = Self::new();
/*
        let mut dstmap: Vec<(usize, IpAddr)> = vec![];
        for dst in ips.dsts {
            dstmap.push((dst.round_trip, dst.ip));
        }
        let sorted = dstmap.sort_by(|a, b| a.0.cmp(&b.0));
        trace!("{:?}", sorted);
*/
        for _ in 0..ips.dsts.len().div_floor(7) {
            let offset = store.pings.lock().unwrap().len() * 7;
            let mut ping = Ping::new();
            for j in 0..7 {
                ping.add(ips.dsts[offset + j].ip);
            }
            store.pings.lock().unwrap().push(ping);
            store.size += 1;
        }
        store
    }

    fn read(&self, addr: usize) -> io::Result<Vec<u8>> {
        trace!("Reading addr 0x{addr:x}");
        let mut datas: Vec<Vec<u8>> = vec![];
        let ping = &self.pings.lock().unwrap()[addr];

        for i in 0..ping.copies {
            let mut data: [u8; 28 + SIZE] = [0; 28 + SIZE];
            ping.socks[i].recv(&mut data)?;
            datas.push(data[28..(28 + SIZE)].to_vec());
        }

        let first: [u8; SIZE] = datas[0].clone()[..].try_into().unwrap();
        let mut good: [u8; SIZE] = datas[0].clone()[..].try_into().unwrap();
        for data in datas[1..].iter() {
            if *data != good && *data == first {
                good = first;
            }
        }
        for i in 0..datas.len() {
            if good != *datas[i] {
                warn!("Sus response data in ping from \"{}\"", ping.ips[i]);
            }
        }
        Ok(good.to_vec())
    }

    async fn write(&self, buf: &[u8], addr: usize, off: usize, size: usize) -> io::Result<()> {
        let mut packets = vec![];
        for i in addr..(size.div_ceil(SIZE)) {
            let loc = i * SIZE;
            packets.push(buf[loc..loc+SIZE].to_vec());
        }
        for (pingspan, packet) in packets.iter().enumerate() {
            let offset = addr + pingspan;
            trace!("Writing addr 0x{offset:x}");
            self.ping(offset, packet)?;
        }
        Ok(())
    }

    fn ping(&self, addr: usize, data: &[u8]) -> io::Result<()> {
        trace!("Sending store ping with addr 0x{addr:x}");
        let mut packet = ICMP_PACKET.to_vec();
        packet.append(&mut data.to_vec());
        let checksum = checksum(&packet);
        packet[2] = checksum[0];
        packet[3] = checksum[1];
        packet[6] = 0;
        packet[7] = 1;
        let ping = &mut self.pings.lock().unwrap()[addr];
        let mut res = vec![];
        for i in 0..ping.copies {
            res.push(ping.socks[i].send(&packet)?);
        }
        Ok(())
    }
}

impl Blocks for PingStore {
    fn read_at(&self, buf: &mut [u8], off: u64) -> io::Result<()> {
        let addr = (off as usize).div_floor(WORD_COUNT);
        let buflen = buf.len();
        let mut res = vec![];
        for pingspan in 0..buflen.div_ceil(SIZE) {
            res.append(&mut self.read(addr + pingspan)?.to_vec());
        }
        //buf.copy_from_slice(&res[0..((addr * 8) - off as usize)]);
        buf.copy_from_slice(&res[0..buflen]);
        Ok(())
    }

    fn write_at(&self, buf: &[u8], off: u64) -> io::Result<()> {
        let addr = (off as usize).div_ceil(WORD_COUNT);
        let buflen = buf.len();
        get_rt("channel pusher", num_cpus::get().div_floor(3) + 1).block_on(
            self.write(buf, addr, (addr * WORD_COUNT) - off as usize, buflen))?;
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok((self.pings.lock().unwrap().len() * 56) as u64)
    }

    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

impl Ping {
    fn new() -> Self {
        Self {
            socks: vec![],
            ips: vec![],
            copies: 0,
        }
    }

    fn add(&mut self, ip: IpAddr) {
        self.socks.push(connect(ip));
        self.ips.push(ip);
        self.copies += 1;
    }
}
