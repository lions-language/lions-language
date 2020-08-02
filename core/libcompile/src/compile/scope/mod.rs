use libtype::{AddressType, AddressValue, AddressKey
    , Type};
use crate::compile::address_dispatch::AddressDispatch;
use crate::compile::ref_count::RefCounter;
use crate::compile::value_buffer::{ValueBuffer, ValueBuferrItem};
use crate::address::{Address};

pub struct Scope {
    address_dispatch: AddressDispatch,
    ref_counter: RefCounter,
    value_buffer: ValueBuffer
}

impl Scope {
    fn alloc_address(&mut self, addr_typ: AddressType) -> Address {
        self.address_dispatch.alloc(addr_typ)
    }

    fn recycle_address(&mut self, addr: AddressValue) {
        self.address_dispatch.recycle_addr(addr);
    }

    fn ref_counter_create(&mut self, r: AddressKey) {
        self.ref_counter.create(r)
    }

    fn ref_counter_remove(&mut self, r: &AddressKey) {
        self.ref_counter.remove(r);
    }

    fn top_n_with_panic_from_value_buffer(&self, n: usize) -> &ValueBuferrItem {
        self.value_buffer.top_n_with_panic(n)
    }

    fn top_n_from_value_buffer(&self, n: usize) -> Option<&ValueBuferrItem> {
        self.value_buffer.top_n(n)
    }

    fn take_top_from_value_buffer(&mut self) -> ValueBuferrItem {
        self.value_buffer.take_top()
    }

    fn push_with_addr_to_value_buffer(&mut self, typ: Type, addr: Address) {
        self.value_buffer.push_with_addr(typ, addr)
    }

    fn push_to_value_buffer(&mut self, typ: Type) {
        self.value_buffer.push(typ)
    }

    pub fn new() -> Self {
        Self {
            address_dispatch: AddressDispatch::new(),
            ref_counter: RefCounter::new(),
            value_buffer: ValueBuffer::new()
        }
    }
}

pub mod context;