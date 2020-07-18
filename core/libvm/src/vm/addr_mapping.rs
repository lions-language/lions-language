use libcompile::address::AddressKey;
use crate::memory::MemoryValue;
use std::collections::HashMap;

pub struct AddressMapping {
    maps: HashMap<AddressKey, MemoryValue>
}

impl AddressMapping {
    pub fn bind(&mut self, key: AddressKey, value: MemoryValue) {
        self.maps.insert(key, value);
    }

    pub fn new() -> Self {
        Self {
            maps: HashMap::new()
        }
    }
}

