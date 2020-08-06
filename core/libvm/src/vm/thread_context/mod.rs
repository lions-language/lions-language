use libtype::{Data, AddressValue
    , AddressKey};
use libmacro::{FieldGet};
use libcommon::ptr::RefPtr;
use scope::context::{ScopeContext};
use crate::memory::stack::RandStack;

#[derive(FieldGet)]
pub struct ThreadMemory {
    stack_data: RandStack<Data>,
}

impl ThreadMemory {
    pub fn new() -> Self {
        Self {
            stack_data: RandStack::<Data>::new()
        }
    }
}

#[derive(FieldGet)]
pub struct ThreadScope {
    scope_context: ScopeContext,
    memory: ThreadMemory
}

impl ThreadScope {
    pub fn get_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr)
        -> RefPtr {
        self.scope_context.current_unchecked().get_data_unchecked(
            addr, link_static, &self.memory)
    }

    pub fn alloc_and_write_data(&mut self, addr: &AddressValue
        , data: Data) {
        let memory = RefPtr::from_ref::<ThreadMemory>(&self.memory);
        self.scope_context.current_mut_unchecked().alloc_and_write_data(
            addr, data, memory);
    }

    pub fn alloc_and_write_static(&mut self, addr: &AddressValue
        , static_addr: AddressKey) {
        self.scope_context.current_mut_unchecked().alloc_and_write_static(
            addr, static_addr);
    }

    pub fn get_last_data_unchecked(&self, addr: &AddressValue
        , link_static: &RefPtr)
        -> RefPtr {
        self.scope_context.last_unchecked().get_data_unchecked(
            addr, link_static, &self.memory)
    }

    pub fn alloc_and_write_last_data(&mut self, addr: &AddressValue
        , data: Data) {
        let memory = RefPtr::from_ref::<ThreadMemory>(&self.memory);
        self.scope_context.last_mut_unchecked().alloc_and_write_data(
            addr, data, memory);
    }

    pub fn alloc_and_write_last_static(&mut self, addr: &AddressValue
        , static_addr: AddressKey) {
        self.scope_context.last_mut_unchecked().alloc_and_write_static(
            addr, static_addr);
    }

    pub fn new() -> Self {
        Self {
            scope_context: ScopeContext::new(),
            memory: ThreadMemory::new()
        }
    }
}

pub mod context;
pub mod scope;
