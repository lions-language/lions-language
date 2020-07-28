use libtype::{self, AddressKey, AddressValue};
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct Address {
    addr: AddressValue
}

impl Address {
    pub fn addr_ref(&self) -> &AddressValue {
        &self.addr
    }

    pub fn addr_clone(&self) -> AddressValue {
        self.addr.clone()
    }

    pub fn addr(self) -> AddressValue {
        self.addr
    }

    pub fn new(addr: AddressValue) -> Self {
        Self {
            addr: addr
        }
    }
}

pub struct PackageIndex {
    indexs: HashMap<String, usize>,
    index: usize
}

mod package;


