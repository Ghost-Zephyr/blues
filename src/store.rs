use std::{
    fs::OpenOptions,
    io::{Write, Read},
    str::from_utf8,
    net::Ipv4Addr,
    vec::Vec};

use log::{trace, debug, error};
use serde::{Deserialize, Serialize};
use crate::{
    scanner::Destination,
    Scanner};

#[derive(Deserialize, Serialize)]
pub struct IPStore {
    pub dsts: Vec<Destination>,
    pub dead: Vec<Ipv4Addr>,
}

impl IPStore {
    pub fn new() -> Self {
        Self { dsts: vec![], dead: vec![] }
    }

    pub fn from_scanner(scanner: &Scanner) -> Self {
//        Self { dsts: scanner.dsts.clone(), dead: scanner.dead.clone() }
        Self { dsts: scanner.dsts.clone(), dead: vec![] }
    }

    pub fn save(&self, file_name: &str) {
        let mut file = OpenOptions::new()
            .write(true).create(true)
            .open(file_name).unwrap();
        match serde_json::to_string(self) {
            Err(err) => {
                error!("Serializing IPStore for saving to file: {:?}", err);
            },
            Ok(out) => {
                match file.write_all(out.as_bytes()) {
                    Err(err) => error!(
                        "Saving IPStore to file \"{}\": {:?}",
                        file_name, err),
                    Ok(ok) => ok
                };
            },
        };
    }

    pub fn load(file_name: &str) -> Self {
        let mut input: Vec<u8> = vec![];

        match OpenOptions::new().read(true).open(file_name) {
            Err(err) => {
                debug!(
                    "Opening IPStore save file \"{}\": {:?}",
                    file_name, err);
                return IPStore::new();
            },

            Ok(mut file) => match file.read_to_end(&mut input) {
                Err(err) => {
                    error!(
                        "Reading IPStore save file \"{}\": {:?}",
                        file_name, err);
                    return IPStore::new();
                },
                Ok(len) => trace!("Read {} bytes from IPStore save file", len),
            }
        }

        let data = from_utf8(&input).unwrap();

        match serde_json::from_str(data) {
            Err(err) => {
                error!("Loading IPStore: {:?}", err);
                IPStore::new()
            },
            Ok(store) => store,
        }
    }
}

impl Default for IPStore {
    fn default() -> Self {
        Self::new()
    }
}
