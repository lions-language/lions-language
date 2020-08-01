use libtype::Data;

#[derive(Clone)]
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

pub trait Rand<T> {
    fn alloc(&mut self, _: T) -> MemoryValue;
    fn free(&mut self, _: MemoryValue);
    fn get_unwrap(&self, index: &MemoryValue) -> &T;
    fn get_mut_unwrap(&mut self, index: &MemoryValue) -> &mut T;
}

pub mod stack;
