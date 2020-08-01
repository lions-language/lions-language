use libtype::{Data, AddressKey};
use crate::compile::{LoadStackContext};

impl LoadStackContext {
    pub fn new(addr: AddressKey, data: Data) -> Self {
        Self {
            addr: addr,
            data: data
        }
    }
}
