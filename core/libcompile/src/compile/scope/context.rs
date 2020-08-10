use libtype::{AddressType, AddressValue
    , AddressKey, Type};
use libcommon::ptr::{RefPtr};
use super::Scope;
use super::{vars::Variant};
use crate::address::Address;
use crate::compile::value_buffer::{
    ValueBufferItem, ValueBufferItemContext};
use std::collections::VecDeque;

pub struct ScopeContext {
    scopes: VecDeque<Scope>
}

pub struct FindVariantResult {
    scope: usize,
    addr: Address
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

    pub fn push_with_addr_context_to_value_buffer(&mut self
        , typ: Type, addr: Address
        , context: ValueBufferItemContext) {
        self.current_mut_unckecked().push_with_addr_context_to_value_buffer(
            typ, addr, context)
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

    /*
     * 查找变量
     * */
    pub fn find_variant(&mut self, name: &str) -> Option<(&String, Variant)> {
        /*
         * 从最后一个向前查找(因为最后一个就是当前作用域), 直到为空
         * */
        let mut index = self.scopes.len() - 1;
        let mut scope = 0;
        let value = match self.find_variant_inner(name, &mut scope, &mut index) {
            Some(v) => {
                v
            },
            None => {
                return None;
            }
        };
        /*
         * 修改 AddressKey 中的 scope 值
         * */
        let (name, var) = value;
        let mut var_addr = var.addr_ref().clone();
        *var_addr.addr_mut().addr_mut().scope_mut() = scope;
        Some((name, Variant::new_with_all(var_addr, var.typ_ref().clone())))
    }

    fn find_variant_inner(&self, name: &str, scope: &mut usize
        , index: &mut usize) -> Option<(&String, &Variant)> {
        match self.scopes.get(*index) {
            Some(sc) => {
                match sc.get_variant_with_key(name) {
                    Some(var) => {
                        /*
                         * 找到 => 递归结束
                         * */
                        return Some(var);
                    },
                    None => {
                        /*
                         * 未找到 => 继续向上
                         * */
                        if *index == 0 {
                            return None;
                        }
                        *index -= 1;
                        *scope += 1;
                        self.find_variant_inner(name, scope, index)
                    }
                }
            },
            None => {
                /*
                 * 到达最上层, 但是还是没找到
                 * */
                return None;
            }
        }
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
