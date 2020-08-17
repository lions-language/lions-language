use libtype::{AddressKey
    , AddressValue
    , AddressType};
use libmacro::{FieldGet, FieldGetMove
    , FieldGetClone};

#[derive(Debug, Clone, FieldGet
    , FieldGetMove, FieldGetClone)]
pub struct MemoryValue{
    addr_value: AddressValue
}

impl MemoryValue {
    pub fn get_ref(&self) -> &AddressKey {
        self.addr_value.addr_ref()
    }

    pub fn get_clone(&self) -> AddressKey {
        self.addr_value.addr_clone()
    }

    pub fn get_single_clone(&self) -> usize {
        self.addr_value.addr_ref().index_ref().clone() as usize
    }

    pub fn new(addr_typ: AddressType
        , addr_key: AddressKey) -> Self {
        Self {
            addr_value: AddressValue::new(
                    addr_typ, addr_key)
        }
    }
}

pub trait Rand<T> {
    fn alloc(&mut self, _: AddressType, _: T) -> MemoryValue;
    fn free(&mut self, _: MemoryValue);
    fn take_unwrap(&mut self, _: &MemoryValue) -> T;
    fn get_unwrap(&self, index: &MemoryValue) -> &T;
    fn get_mut_unwrap(&mut self, index: &MemoryValue) -> &mut T;
}

pub mod stack;
