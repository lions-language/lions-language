use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetMove
    , FieldGetClone, NewWithAll};
use libtype::{AddressType, AddressValue, AddressKey
    , Type, TypeAttrubute};
use libtype::function::{FunctionReturn};
use crate::compile::address_dispatch::AddressDispatch;
use crate::compile::ref_count::RefCounter;
use crate::compile::value_buffer::{ValueBuffer
    , ValueBufferItem, ValueBufferItemContext};
use crate::address::{Address};
use std::cmp::{PartialEq};
use std::collections::VecDeque;

#[derive(Debug, PartialEq)]
pub enum ScopeType {
    Function,
    Block
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetClone, FieldGetMove
    , Clone)]
pub struct ScopeFuncCall {
    is_auto_call_totype: bool,
    expect_type: Type
}

#[derive(FieldGet, FieldGetMove)]
pub struct Scope {
    scope_typ: ScopeType,
    address_dispatch: AddressDispatch,
    ref_counter: RefCounter,
    vars: vars::Variants,
    value_buffer: ValueBuffer,
    /*
     * 如果作用域是函数, 那么下面的字段一定需要被填充
     * */
    func_return: Option<FunctionReturn>,
    func_call_stack: VecDeque<ScopeFuncCall>,
    /*
     * 记录函数传入参数的地址索引, 用于 return 语句的时候, 如果是引用类型, 判断引用的是哪个输入参数
     * */
    func_param_addr_index: Option<Vec<(usize, TypeAttrubute)>>,
    /* 记录 return 语句 的跳转指令索引
     * */
    return_jumps: Option<Vec<usize>>,
    structinit_field_stack: Option<VecDeque<String>>
}

impl Scope {
    fn alloc_address(&mut self, addr_typ: AddressType, scope: usize) -> Address {
        self.address_dispatch.alloc(addr_typ, scope)
    }

    fn recycle_address(&mut self, addr: AddressValue) {
        // println!("recycle_address");
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

    fn set_function_return(&mut self, func_return: FunctionReturn) {
        *&mut self.func_return = Some(func_return);
    }

    fn enter_func_call(&mut self) {
        self.func_call_stack.push_back(ScopeFuncCall::default());
    }

    fn leave_func_call(&mut self) {
        self.func_call_stack.pop_back();
    }

    fn set_current_func_call(&mut self, func_call: ScopeFuncCall) {
        *self.func_call_stack.back_mut().expect("should not happend, enter func call first")
            = func_call;
    }

    fn get_current_func_call(&self) -> Option<&ScopeFuncCall> {
        self.func_call_stack.back()
    }

    pub fn add_return_jump(&mut self, index: usize) {
        match &mut self.return_jumps {
            Some(v) => {
                v.push(index);
            },
            None => {
                self.return_jumps = Some(vec![index]);
            }
        }
    }

    pub fn get_all_return_jumps_ref(&self) -> &Option<Vec<usize>> {
        &self.return_jumps
    }

    pub fn add_func_param_addr_index(&mut self, addr_index: usize
        , typ_attr: TypeAttrubute) {
        match &mut self.func_param_addr_index {
            Some(v) => {
                v.push((addr_index, typ_attr));
            },
            None => {
                self.func_param_addr_index = Some(vec![(addr_index, typ_attr)]);
            }
        }
    }

    pub fn get_all_func_param_addr_index_ref(&self) -> &Option<Vec<(usize, TypeAttrubute)>> {
        &self.func_param_addr_index
    }

    pub fn enter_structinit_field_stack(&mut self, name: String) {
        match &mut self.structinit_field_stack {
            Some(v) => {
                v.push_back(name);
            },
            None => {
                let mut vec = VecDeque::new();
                vec.push_back(name);
                self.structinit_field_stack = Some(vec);
            }
        }
    }

    pub fn leave_structinit_field_stack(&mut self) -> Option<String> {
        match &mut self.structinit_field_stack {
            Some(v) => {
                v.pop_back()
            },
            None => {
                None
            }
        }
    }

    pub fn get_structinit_field_stack_len(&self) -> usize {
        match &self.structinit_field_stack {
            Some(v) => {
                v.len()
            },
            None => {
                0
            }
        }
    }

    pub fn get_last_n_structinit_field_stack(&self, n: usize) -> Option<&String> {
        let stack = match &self.structinit_field_stack {
            Some(v) => {
                v
            },
            None => {
                return None;
            }
        };
        let len = stack.len();
        if len == 0 || len - 1 < n {
            return None;
        }
        let index = len - 1 - n;
        stack.get(index)
    }

    pub fn new_with_addr_start(start: usize, scope_typ: ScopeType) -> Self {
        Self {
            scope_typ: scope_typ,
            address_dispatch: AddressDispatch::new_with_start(start),
            ref_counter: RefCounter::new(),
            vars: vars::Variants::new(),
            value_buffer: ValueBuffer::new(),
            func_return: None,
            func_call_stack: VecDeque::new(),
            func_param_addr_index: None,
            return_jumps: None,
            structinit_field_stack: None
        }
    }

    pub fn new(scope_typ: ScopeType) -> Self {
        Scope::new_with_addr_start(0, scope_typ)
    }
}

pub mod context;
pub mod vars;
