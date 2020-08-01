use libtype::{self, AddressKey, AddressValue};
use libmacro::{FieldGet};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, FieldGet)]
pub struct Address {
    addr: AddressValue
}

impl Address {
    pub fn addr_clone(&self) -> AddressValue {
        self.addr.clone()
    }

    pub fn addr_key(self) -> AddressKey {
        self.addr.addr()
    }
    
    pub fn addr_key_clone(&self) -> AddressKey {
        self.addr.addr_ref().clone()
    }

    pub fn is_invalid(&self) -> bool {
        self.addr.is_invalid()
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


