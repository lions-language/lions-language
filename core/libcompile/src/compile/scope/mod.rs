use libmacro::{FieldGet, FieldGetMove};
use libtype::{AddressType, AddressValue, AddressKey
    , Type, TypeAttrubute};
use crate::compile::address_dispatch::AddressDispatch;
use crate::compile::ref_count::RefCounter;
use crate::compile::value_buffer::{ValueBuffer
    , ValueBufferItem, ValueBufferItemContext};
use crate::address::{Address};

#[derive(FieldGet, FieldGetMove)]
pub struct Scope {
    address_dispatch: AddressDispatch,
    ref_counter: RefCounter,
    vars: vars::Variants,
    value_buffer: ValueBuffer
}

impl Scope {
    fn alloc_address(&mut self, addr_typ: AddressType, scope: usize) -> Address {
        self.address_dispatch.alloc(addr_typ, scope)
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

    fn top_n_with_panic_from_value_buffer(&self, n: usize) -> &ValueBufferItem {
        self.value_buffer.top_n_with_panic(n)
    }

    fn top_n_from_value_buffer(&self, n: usize) -> Option<&ValueBufferItem> {
        self.value_buffer.top_n(n)
    }

    fn take_top_from_value_buffer(&mut self) -> ValueBufferItem {
        self.value_buffer.take_top()
    }

    fn push_with_addr_to_value_buffer(&mut self, typ: Type, addr: Address) {
        self.value_buffer.push_with_addr(typ, addr);
    }

    fn push_with_addr_typattr_to_value_buffer(&mut self, typ: Type, addr: Address
        , typ_attr: TypeAttrubute) {
        self.value_buffer.push_with_addr_typattr(typ, addr, typ_attr);
    }

    fn push_with_addr_context_to_value_buffer(&mut self, typ: Type, addr: Address
        , context: ValueBufferItemContext) {
        self.value_buffer.push_with_addr_context(typ, addr, context);
    }

    fn push_with_addr_context_typattr_to_value_buffer(&mut self, typ: Type
        , addr: Address, context: ValueBufferItemContext
        , typ_attr: TypeAttrubute) {
        self.value_buffer.push_with_addr_context_typattr(typ
            , addr, context, typ_attr);
    }

    fn push_to_value_buffer(&mut self, typ: Type) {
        self.value_buffer.push(typ)
    }

    fn add_variant(&mut self, name: String, var: vars::Variant) {
        self.vars.add(name, var);
    }

    fn remove_variant(&mut self, name: &String) {
        self.vars.remove(name);
    }

    fn get_variant(&self, name: &str) -> Option<&vars::Variant> {
        self.vars.get(name)
    }

    fn get_variant_with_key(&self, name: &str) -> Option<(&String, &vars::Variant)> {
        self.vars.get_with_key(name)
    }

    fn get_variant_mut(&mut self, name: &str) -> Option<&mut vars::Variant> {
        self.vars.get_mut(name)
    }

    pub fn new() -> Self {
        Self {
            address_dispatch: AddressDispatch::new(),
            ref_counter: RefCounter::new(),
            vars: vars::Variants::new(),
            value_buffer: ValueBuffer::new(),
        }
    }
}

pub mod context;
pub mod vars;
