use crate::memory::stack::RandStack;
use crate::vm::addr_mapping::{AddressMapping};

pub struct Scope {
    static_stack: RandStack<usize>,
    static_addr_mapping: AddressMapping,
    stack_addr_mapping: AddressMapping
}

impl Scope {
    pub fn new() -> Self {
        Self {
            static_stack: RandStack::<usize>::new(),
            static_addr_mapping: AddressMapping::new(),
            stack_addr_mapping: AddressMapping::new()
        }
    }
}

pub mod context;
