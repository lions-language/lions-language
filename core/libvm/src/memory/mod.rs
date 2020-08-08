use libtype::{Data, AddressKey};

#[derive(Debug, Clone)]
pub struct MemoryValue(AddressKey);

impl MemoryValue {
    pub fn get_ref(&self) -> &AddressKey {
        &self.0
    }

    pub fn get_clone(&self) -> AddressKey {
        self.0.clone()
    }

    pub fn get_single_clone(&self) -> usize {
        self.0.index_ref().clone() as usize
    }

    pub fn new(v: AddressKey) -> Self {
        Self(v)
    }
}

pub trait Rand<T> {
    fn alloc(&mut self, _: T) -> MemoryValue;
    fn free(&mut self, _: MemoryValue);
    fn get_unwrap(&self, index: &MemoryValue) -> &T;
    fn get_mut_unwrap(&mut self, index: &MemoryValue) -> &mut T;
}

pub mod stack;
