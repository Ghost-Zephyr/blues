#![feature(bigint_helper_methods)]
#![feature(async_closure)]
#![feature(int_roundings)]
#![feature(never_type)]
#![feature(ip)]

pub mod scanner;
pub mod pinger;
pub mod blocks;
pub mod store;
pub use blocks::PingStore;
pub use scanner::Scanner;
pub use pinger::{
    ICMP_PACKET, TIMEOUT, Pinger};
pub use store::IPStore;

#[inline]
pub fn checksum(bytes: &[u8]) -> [u8; 2] {
    let mut calc = internet_checksum::Checksum::new();
    calc.add_bytes(bytes);
    calc.checksum()
}

#[inline]
pub fn get_rt(name: &str, threads: usize) -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name(name)
        .build() {
            Err(err) => panic!("Unable to build tokio runtime! {:?}", err),
            Ok(rt) => rt,
        }
}
