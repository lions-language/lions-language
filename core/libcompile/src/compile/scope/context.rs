use libtype::{AddressType, AddressValue
    , AddressKey, Type};
use super::Scope;
use super::{vars::Variant};
use crate::address::Address;
use crate::compile::value_buffer::{ValueBufferItem};
use std::collections::VecDeque;

pub struct ScopeContext {
    scopes: VecDeque<Scope>
}

impl ScopeContext {
    pub fn enter(&mut self) {
        self.scopes.push_back(Scope::new());
    }

    pub fn leave(&mut self) {
        self.scopes.pop_back();
    }

    pub fn alloc_address(&mut self, addr_typ: AddressType
        , scope: usize) -> Address {
        /*
         * 即使是最外层的函数进入的时候也一定需要调用 enter, 所以栈中一定存在元素
         * */
        self.current_mut_unckecked().alloc_address(addr_typ, scope)
    }

    pub fn recycle_address(&mut self, addr: AddressValue) {
        self.current_mut_unckecked().recycle_address(addr);
    }

    pub fn current_mut_unckecked(&mut self) -> &mut Scope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unckecked(&self) -> &Scope {
        self.scopes.back().expect("should not happend")
    }

    pub fn ref_counter_create(&mut self, r: AddressKey) {
        self.current_mut_unckecked().ref_counter_create(r)
    }

    pub fn ref_counter_remove(&mut self, r: &AddressKey) {
        self.current_mut_unckecked().ref_counter_remove(r);
    }

    pub fn top_n_with_panic_from_value_buffer(&self, n: usize) -> &ValueBufferItem {
        self.current_unckecked().top_n_with_panic_from_value_buffer(n)
    }

    pub fn top_n_from_value_buffer(&self, n: usize) -> Option<&ValueBufferItem> {
        self.current_unckecked().top_n_from_value_buffer(n)
    }

    pub fn take_top_from_value_buffer(&mut self) -> ValueBufferItem {
        self.current_mut_unckecked().take_top_from_value_buffer()
    }

    pub fn push_with_addr_to_value_buffer(&mut self, typ: Type, addr: Address) {
        self.current_mut_unckecked().push_with_addr_to_value_buffer(typ, addr)
    }

    pub fn push_to_value_buffer(&mut self, typ: Type) {
        self.current_mut_unckecked().push_to_value_buffer(typ)
    }

    pub fn add_variant(&mut self, name: String, var: Variant) {
        self.current_mut_unckecked().add_variant(name, var);
    }

    pub fn remove_variant_unchecked(&mut self, scope: usize, name: &String) {
        self.get_back_mut_n_unchecked(scope).remove_variant(name);
    }

    fn get_back_mut_n_unchecked(&mut self, n: usize) -> &mut Scope {
        let len = self.scopes.len();
        self.scopes.get_mut(len - 1 - n).expect(&format!("len: {}, n: {}", len, n))
    }

    pub fn new_with_first() -> Self {
        let mut scopes = VecDeque::new();
        scopes.push_back(Scope::new());
        Self {
            scopes: scopes
        }
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}
