use libtype::AddressKey;
use crate::memory::MemoryValue;
use std::collections::HashMap;
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Debug, PartialEq, Eq, Hash)]
struct Key(usize, usize);

impl From<AddressKey> for Key {
    fn from(v: AddressKey) -> Self {
        let (index, offset, lengthen_offset, _, length) = v.fields_move();
        Key(index as usize, lengthen_offset)
    }
}

impl From<&AddressKey> for Key {
    fn from(v: &AddressKey) -> Self {
        Key(v.index_clone() as usize, v.lengthen_offset_clone())
    }
}

pub struct AddressMapping {
    maps: HashMap<Key, MemoryValue>
}

impl AddressMapping {
    pub fn bind(&mut self, key: AddressKey, value: MemoryValue) {
        self.maps.insert(Key::from(key), value);
        // println!("{:?}", self.maps);
    }

    pub fn remove(&mut self, key: AddressKey) {
        self.maps.remove(&Key::from(key));
    }

    pub fn get_unwrap(&self, key: &AddressKey) -> &MemoryValue {
        self.maps.get(&Key::from(key)).expect(&format!("address key: {:?}, maps: {:?}"
                , key, &self.maps))
    }

    pub fn exists(&self, key: &AddressKey) -> bool {
        if self.maps.get(&Key::from(key)).is_some() {
            true
        } else {
            false
        }
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

