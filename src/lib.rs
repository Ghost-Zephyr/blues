#![feature(bigint_helper_methods)]
//#![feature(async_closure)]
#![feature(int_roundings)]
#![feature(never_type)]
#![feature(ip)]

pub mod scanner;
//pub mod pinger;
pub mod blocks;
mod store;
pub use blocks::PingStore;
pub use scanner::Scanner;
//pub use pinger::Pinger;
pub use store::IPStore;

/// ICMP packet header template
pub const ICMP_PACKET: [u8; 8] = [
    8, 0, // 8 Echo ping request, code 0
    0, 0, // Index 2 and 3 are for ICMP checksum
    0xde, 0xad, // Identifier
    0, 1, // Sequence numbers
];

pub const SIZE: usize = 64; // Bytes of echo data in each ping
pub const PACKET_SIZE: usize = SIZE + 16; // Echo data size plus rest of ICMP packet
pub const BYTE_COUNT: usize = SIZE / 8;

pub static mut TIMEOUT: Option<std::time::Duration> = None;

/// Get an IcmpSocket from IpAddr and set the global timeout on the socket
pub fn connect(ip: std::net::IpAddr) -> icmp::IcmpSocket {
    let sock = match icmp::IcmpSocket::connect(ip) {
        Err(err) => panic!("Unable to open ICMP socket: {err:?}"),
        Ok(sock) => sock,
    };
    let timeout = unsafe { TIMEOUT };
    if timeout.is_none() {
        return sock;
    }
    if let Err(err) = sock.set_write_timeout(timeout) {
        log::debug!("unable to set write timeout on socket: {}", err);
    };
    if let Err(err) = sock.set_read_timeout(timeout) {
        log::debug!("unable to set read timeout on socket: {}", err);
    };
    sock
}

#[inline]
/// Get a random IPv4 address
pub fn rand_ip4() -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(rand::random(), rand::random(), rand::random(), rand::random())
}

#[inline]
/// Get a random globaly accessible IP address
pub fn rand_ip() -> std::net::Ipv4Addr {
    let mut ip = rand_ip4();
    while !ip.is_global() { ip = rand_ip4() };
    //std::net::IpAddr::V4(ip)
    ip
}

#[inline]
/// Calculate the "internet checksum"
pub fn checksum(bytes: &[u8]) -> [u8; 2] {
    let mut calc = internet_checksum::Checksum::new();
    calc.add_bytes(bytes);
    calc.checksum()
}

#[inline]
/// Get a new tokio multi thread runtime
pub fn get_rt(name: &str, threads: usize) -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name(name)
        .build() {
            Err(err) => panic!("Unable to build tokio runtime! {err:?}"),
            Ok(rt) => rt,
        }
}
