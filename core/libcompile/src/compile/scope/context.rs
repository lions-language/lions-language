use libresult::{DescResult};
use libtype::{AddressType, AddressValue
    , AddressKey, Type, TypeAttrubute};
use libtype::function::{FunctionReturn};
use libcommon::ptr::{RefPtr};
use super::{Scope, ScopeType, ScopeFuncCall};
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
    pub fn enter(&mut self, scope_typ: ScopeType) {
        self.scopes.push_back(Scope::new(scope_typ));
    }

    pub fn enter_with_addr_start(&mut self, start: usize
        , scope_typ: ScopeType) {
        self.scopes.push_back(Scope::new_with_addr_start(start, scope_typ));
    }

    pub fn leave(&mut self) {
        self.scopes.pop_back();
    }

    pub fn alloc_address(&mut self, addr_typ: AddressType
        , scope: usize, length: usize) -> Address {
        /*
         * 即使是最外层的函数进入的时候也一定需要调用 enter, 所以栈中一定存在元素
         * */
        self.current_mut_unchecked().alloc_address(addr_typ, scope, length)
        // self.get_back_mut_n_unchecked(scope).alloc_address(addr_typ, scope)
    }

    pub fn alloc_address_with_index(&mut self, typ: AddressType
        , index: usize, scope: usize, length: usize) -> Address {
        self.current_mut_unchecked().alloc_with_index(typ, index, scope, length)
    }

    pub fn update_addr_index(&mut self, index: usize) {
        self.current_mut_unchecked().update_addr_index(index);
    }

    pub fn addr_is_valid(&self, addr: &AddressValue) -> bool {
        let scope = *addr.addr_ref().scope_ref();
        self.get_back_n_unchecked(scope).addr_is_valid(addr)
    }

    pub fn use_addr(&mut self, addr: &AddressValue) {
        let scope = *addr.addr_ref().scope_ref();
        self.get_back_mut_n_unchecked(scope).use_addr(addr.addr_ref());
    }

    pub fn alloc_continuous_address(&mut self, length: usize) -> usize {
        self.current_mut_unchecked().alloc_continuous_address(length)
    }

    pub fn alloc_address_last_n(&mut self, addr_typ: AddressType
        , scope: usize, length: usize) -> Address {
        /*
         * 即使是最外层的函数进入的时候也一定需要调用 enter, 所以栈中一定存在元素
         * */
        self.get_back_mut_n_unchecked(scope).alloc_address(addr_typ, 0, length)
    }

    pub fn recycle_address(&mut self, addr: AddressValue) {
        let scope = *addr.addr_ref().scope_ref();
        self.get_back_mut_n_unchecked(scope).recycle_address(addr);
    }

    pub fn current_mut_unchecked(&mut self) -> &mut Scope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unchecked(&self) -> &Scope {
        self.scopes.back().expect("should not happend")
    }

    pub fn last_n_mut_unchecked(&mut self, n: usize) -> &mut Scope {
        self.scopes.get_mut(self.scopes.len() - 1 - n).expect("should not happend")
    }

    pub fn last_n_unchecked(&self, n: usize) -> &Scope {
        self.scopes.get(self.scopes.len() - 1 - n).expect("should not happend")
    }

    pub fn ref_counter_create(&mut self, r: AddressKey) {
        self.current_mut_unchecked().ref_counter_create(r)
    }

    pub fn ref_counter_remove(&mut self, r: &AddressKey) {
        self.current_mut_unchecked().ref_counter_remove(r);
    }

    pub fn top_n_with_panic_from_value_buffer(&self, n: usize) -> &ValueBufferItem {
        self.current_unchecked().top_n_with_panic_from_value_buffer(n)
    }

    pub fn top_n_from_value_buffer(&self, n: usize) -> Option<&ValueBufferItem> {
        self.current_unchecked().top_n_from_value_buffer(n)
    }

    pub fn take_top_from_value_buffer(&mut self) -> Result<ValueBufferItem, DescResult> {
        let item = self.current_mut_unchecked().take_top_from_value_buffer();
        if !self.addr_is_valid(item.addr_ref().addr_ref()) {
            return Err(DescResult::Error(format!("be moved")));
        }
        Ok(item)
    }

    pub fn push_with_addr_to_value_buffer(&mut self, typ: Type, addr: Address) {
        self.current_mut_unchecked().push_with_addr_to_value_buffer(typ, addr)
    }

    pub fn push_with_addr_typattr_to_value_buffer(&mut self, typ: Type, addr: Address
        , typ_attr: TypeAttrubute) {
        self.current_mut_unchecked().push_with_addr_typattr_to_value_buffer(
            typ, addr, typ_attr)
    }

    pub fn push_with_addr_context_to_value_buffer(&mut self
        , typ: Type, addr: Address
        , context: ValueBufferItemContext) {
        self.current_mut_unchecked().push_with_addr_context_to_value_buffer(
            typ, addr, context)
    }

    pub fn push_with_addr_context_typattr_to_value_buffer(&mut self
        , typ: Type, addr: Address
        , context: ValueBufferItemContext
        , typ_attr: TypeAttrubute) {
        self.current_mut_unchecked().push_with_addr_context_typattr_to_value_buffer(
            typ, addr, context, typ_attr)
    }

    pub fn push_to_value_buffer(&mut self, typ: Type) {
        self.current_mut_unchecked().push_to_value_buffer(typ)
    }

    pub fn add_variant(&mut self, name: String, var: Variant) {
        self.current_mut_unchecked().add_variant(name, var);
    }

    pub fn remove_variant_unchecked(&mut self, scope: usize, name: &str, addr: &AddressKey) {
        self.get_back_mut_n_unchecked(scope).remove_variant(name, addr);
    }

    fn get_back_mut_n_unchecked(&mut self, n: usize) -> &mut Scope {
        let len = self.scopes.len();
        // println!("{}, {}", len, n);
        self.scopes.get_mut(len - 1 - n).expect(&format!("len: {}, n: {}", len, n))
    }

    fn get_back_n_unchecked(&self, n: usize) -> &Scope {
        let len = self.scopes.len();
        // println!("{}, {}", len, n);
        self.scopes.get(len - 1 - n).expect(&format!("len: {}, n: {}", len, n))
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
        *var_addr.addr_mut().addr_mut().scope_mut() += scope;
        // println!("--- {}, {}", var_addr.addr_mut().addr_mut().scope_ref(), scope);
        Some((name, Variant::new(var_addr, var.typ_ref().clone()
                    , var.typ_attr_ref().clone())))
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

    pub fn get_last_function_scope_unchecked(&mut self) -> usize {
        self.get_last_scope_type_index(&ScopeType::Function).expect("should not happend")
    }

    pub fn get_last_scope_type_index(&mut self, scope_typ: &ScopeType) -> Option<usize> {
        let mut index = self.scopes.len() - 1;
        let mut scope = 0;
        if !self.get_last_scope_type_index_inner(scope_typ, &mut index
            , &mut scope) {
            return None;
        }
        Some(scope)
    }

    fn get_last_scope_type_index_inner(&mut self, scope_typ: &ScopeType
        , index: &mut usize, scope: &mut usize) -> bool {
        let sp = match self.scopes.get(*index) {
            Some(sp) => {
                sp
            },
            None => {
                return false;
            }
        };
        let current_scope_typ = sp.scope_typ_ref();
        if scope_typ == current_scope_typ {
            /*
             * 检测到类型相等 => 返回
             * */
            return true;
        } else {
            if *index == 0 {
                return false;
            }
            *index -= 1;
            *scope += 1;
            return self.get_last_scope_type_index_inner(scope_typ, index, scope);
        }
    }

    pub fn set_current_func_return(&mut self, func_return: FunctionReturn) {
        self.current_mut_unchecked().set_function_return(func_return);
    }

    pub fn get_current_func_return_ref(&self) -> Option<&FunctionReturn> {
        self.current_unchecked().func_return_ref().as_ref()
    }

    pub fn enter_func_call(&mut self) {
        self.current_mut_unchecked().enter_func_call();
    }

    pub fn leave_func_call(&mut self) {
        self.current_mut_unchecked().leave_func_call();
    }

    pub fn set_current_func_call(&mut self, func_call: ScopeFuncCall) {
        self.current_mut_unchecked().set_current_func_call(func_call);
    }

    pub fn get_current_func_call(&self) -> Option<&ScopeFuncCall> {
        self.current_unchecked().get_current_func_call()
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}
