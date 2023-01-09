use std::{
    time::{Duration, Instant},
    net::{Ipv4Addr, IpAddr},
    io};

use log::{trace, debug, info};
use icmp::IcmpSocket;
use rand::random;
use crate::checksum;

pub static mut TIMEOUT: Option<Duration> = None;

pub static ICMP_PACKET: [u8; 8] = [
    8, 0, // 8 Echo ping request, code 0
    0, 0, // Index 2 and 3 are for ICMP checksum
    0xde, 0xad, // Identifier
    0, 1, // Sequence numbers
];

pub struct PingResponse {
    pub round_trip: usize,
    pub corrupt: bool,
    pub small: bool,
    pub data: [u8; 84],
}

pub type PingResult = Result<PingResponse, io::Error>;

pub struct Pinger {
    pub data: [u8; 64],
    pub seq: [u8; 2],
}

impl Pinger {
    pub fn new() -> Self {
        Self {
            data: [0; 64],
            seq: [1, 0],
        }
    }

    pub fn data(mut self, data: [u8; 64]) -> Self {
        self.data = data;
        self
    }

    pub fn ping(&mut self, ip: IpAddr) -> PingResult {
        let mut pack = ICMP_PACKET.to_vec();
        pack[6] = self.seq[1];
        pack[7] = self.seq[0];
        pack.append(&mut self.data.clone().to_vec());

        let checksum = checksum(&pack);
        pack[2] = checksum[0];
        pack[3] = checksum[1];

        let mut socket = connect(ip);
        let start = Instant::now();

        match socket.send(&pack) {
            Err(err) => {
                debug!("Was unable to ping IP {}: {:?}", ip, err);
                return Err(err);
            },
            Ok(count) => if count != pack.len() {
                debug!("Sent {} of {} bytes to {}", count, pack.len(), ip);
            },
        };
        self.inc_seq();

        let mut response: [u8; 64 + 20] = [0; 64 + 20];

        match socket.recv(&mut response) {
            Err(err) => {
                info!("Error scanning IP \"{}\": {:?}", ip, err);
                Err(err)
            }

            Ok(size) => {
                let mut result = PingResponse::new(response, start.elapsed().as_millis() as usize);
                if size != 84 {
                    debug!("Didn't revice full response from \"{}\"", ip);
                    trace!("Response in question: {:?}", response);
                    result.corrupt = true;
                }
                if response[20 + 8..] != self.data {
                    if response[56..] == self.data[..28] {
                        result.small = true
                    } else {
                        debug!("Response payload was not the same as request in ping to \"{}\"", ip);
                        trace!("Response in question: {:?}", response);
                        result.corrupt = true;
                    }
                }
                Ok(result)
            }
        }
    }

    fn inc_seq(&mut self) {
        let mut carry = false;
        (self.seq[0], carry) = self.seq[0].carrying_add(1, carry);
        if carry {
            carry = false;
            (self.seq[1], carry) = self.seq[1].carrying_add(1, carry);
        }
        if carry {
            self.seq = [1, 0];
        }
    }
}

pub fn connect(ip: IpAddr) -> IcmpSocket {
    let sock = match IcmpSocket::connect(ip) {
        Err(err) => panic!("Unable to open ICMP socket: {err:?}"),
        Ok(sock) => sock,
    };
    let timeout = unsafe { TIMEOUT };
    if timeout.is_none() {
        return sock;
    }
    if let Err(err) = sock.set_write_timeout(timeout) {
        debug!("unable to set write timeout on socket: {}", err);
    };
    if let Err(err) = sock.set_read_timeout(timeout) {
        debug!("unable to set read timeout on socket: {}", err);
    };
    sock
}

#[inline]
fn rand_ip4() -> Ipv4Addr {
    Ipv4Addr::new(random(), random(), random(), random())
}

#[inline]
pub fn rand_ip() -> IpAddr {
    let mut ip = rand_ip4();
    while !ip.is_global() { ip = rand_ip4() };
    IpAddr::V4(ip)
}

impl PingResponse {
    fn new(data: [u8; 84], round_trip: usize) -> Self {
        Self {
            round_trip,
            corrupt: false,
            small: false,
            data,
        }
    }
}

impl Default for PingResponse {
    fn default() -> Self {
        Self::new([0; 84], 0)
    }
}

impl Default for Pinger {
    fn default() -> Self {
        Self::new()
    }
}
