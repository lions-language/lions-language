use libtype::AddressKey;
use crate::memory::MemoryValue;
use std::collections::HashMap;

pub struct AddressMapping {
    maps: HashMap<u64, MemoryValue>
}

impl AddressMapping {
    pub fn bind(&mut self, key: AddressKey, value: MemoryValue) {
        self.maps.insert(key.index(), value);
    }

    pub fn remove(&mut self, key: AddressKey) {
        self.maps.remove(key.index_ref());
    }

    pub fn get_unwrap(&self, key: &AddressKey) -> &MemoryValue {
        self.maps.get(key.index_ref()).expect(&format!("address key: {:?}, maps: {:?}"
                , key, &self.maps))
    }

    pub fn print(&self) {
        for value in self.maps.iter() {
            println!("{:?}", value);
        }
    }

    pub fn new() -> Self {
        Self {
            maps: HashMap::new()
        }
    }
}

