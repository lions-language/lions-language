use crate::data::Data;

pub struct MemoryValue(usize);

impl MemoryValue {
    pub fn get_ref(&self) -> &usize {
        &self.0
    }

    pub fn get(&self) -> usize {
        self.0
    }

    pub fn new(v: usize) -> Self {
        Self(v)
    }
}

pub trait Memory {
    fn alloc(&mut self, _: Data) -> MemoryValue;
    fn free(&mut self, _: MemoryValue);
}

pub mod stack;
