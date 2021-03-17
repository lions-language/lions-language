use libresult::DescResult;
use libcommon::ptr::{HeapPtr, RefPtr};
use libmacro::{FieldGet, FieldGetMove
    , FieldGetClone, NewWithAll};
use libtype::{AddressType, AddressValue, AddressKey
    , Type, TypeAttrubute};
use libtype::function::{FunctionReturn};
use libtype::package::PackageStr;
use crate::compile::address_dispatch::AddressDispatch;
use crate::compile::ref_count::RefCounter;
use crate::compile::value_buffer::{ValueBuffer
    , ValueBufferItem, ValueBufferItemContext};
use crate::address::{Address};
use crate::define::{DefineObject};
use std::cmp::{PartialEq};
use std::collections::VecDeque;

#[derive(Debug, PartialEq)]
pub enum ScopeType {
    Function,
    Block,
    BlockDefine
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetClone, FieldGetMove
    , Clone)]
pub struct ScopeFuncCall {
    is_auto_call_totype: bool,
    expect_type: Type
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetClone, FieldGetMove
    , Clone)]
pub struct StructInitField {
    name: String,
    field: RefPtr
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetClone, FieldGetMove
    , Clone)]
pub struct StructInit {
    define: HeapPtr,
    addr_index: usize,
    addr_length: usize,
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetClone, FieldGetMove
    , Clone)]
pub struct PointAccess {
    typ: Type,
    typ_attr: TypeAttrubute,
    addr_value: AddressValue,
    object_typ_attr: TypeAttrubute
}

#[derive(Default, FieldGet, NewWithAll
    , FieldGetClone, FieldGetMove
    , Clone)]
pub struct ColonColonAccess {
    prefix: String
}

#[derive(FieldGet, FieldGetMove)]
pub struct Scope {
    scope_typ: ScopeType,
    define_obj: DefineObject,
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
    /* 
     * 记录 return 语句 的跳转指令索引
     * */
    return_jumps: Option<Vec<usize>>,
    structinit_field_stack: Option<VecDeque<StructInitField>>,
    structinit_stack: Option<VecDeque<StructInit>>,
    /*
     * . 操作符
     * */
    point_access: Option<VecDeque<PointAccess>>,
    point_access_fullname: Option<String>,
    /*
     * :: 操作符
     * */
    colon_colon_access: Option<ColonColonAccess>
}

impl Scope {
    fn alloc_address(&mut self, addr_typ: AddressType, scope: usize
        , length: usize) -> Address {
        self.address_dispatch.alloc(addr_typ, scope, length)
    }

    /*
    pub fn alloc_with_index(&mut self, typ: AddressType
        , index: usize, scope: usize, length: usize) -> Address {
        self.address_dispatch.alloc_with_index(typ, index, scope, length)
    }
    */

    pub fn set_define_obj(&mut self, define_obj: DefineObject) {
        *&mut self.define_obj = define_obj;
    }

    pub fn get_define_obj_ref(&self) -> &DefineObject {
        &self.define_obj
    }

    pub fn get_define_obj_clone(&self) -> DefineObject {
        self.define_obj.clone()
    }

    pub fn update_addr_index(&mut self, index: usize) {
        self.address_dispatch.update_addr_index(index);
    }

    fn addr_is_valid(&self, addr: &AddressValue) -> bool {
        self.address_dispatch.addr_is_valid(addr)
    }

    pub fn use_addr(&mut self, addr: &AddressKey) {
        self.address_dispatch.use_addr(addr);
    }

    fn alloc_continuous_address(&mut self, length: usize) -> usize {
        self.address_dispatch.alloc_continuous(length)
    }

    pub fn next_new_addr_index(&self) -> usize {
        self.address_dispatch.next_new_addr_index()
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

    fn push_full_to_value_buffer(&mut self, typ: Type
        , addr: Address, context: ValueBufferItemContext
        , typ_attr: TypeAttrubute, package_str: PackageStr) {
        self.value_buffer.push_full(typ
            , addr, context, typ_attr, package_str);
    }

    fn push_to_value_buffer(&mut self, typ: Type) {
        self.value_buffer.push(typ)
    }

    fn add_variant(&mut self, name: String, var: vars::Variant) {
        self.vars.add(name, var);
    }

    fn remove_variant(&mut self, name: &str, addr: &AddressKey) {
        self.vars.remove(name, addr);
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

    pub fn enter_structinit_field_stack(&mut self, name: StructInitField) {
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

    pub fn leave_structinit_field_stack(&mut self) -> Option<StructInitField> {
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

    pub fn get_current_mut_structinit_field_stack_unchecked(&mut self) -> &mut StructInitField {
        self.get_current_mut_structinit_field_stack().expect("should not happend")
    }

    pub fn get_current_mut_structinit_field_stack(&mut self) -> Option<&mut StructInitField> {
        match &mut self.structinit_field_stack {
            Some(v) => {
                v.back_mut()
            },
            None => {
                None
            }
        }
    }

    pub fn get_current_structinit_field_stack_unchecked(&self) -> &StructInitField {
        self.get_current_structinit_field_stack().expect("should not happend")
    }

    pub fn get_current_structinit_field_stack(&self) -> Option<&StructInitField> {
        match &self.structinit_field_stack {
            Some(v) => {
                v.back()
            },
            None => {
                None
            }
        }
    }

    pub fn get_last_n_mut_structinit_field_stack(&mut self, n: usize) -> Option<&mut StructInitField> {
        let stack = match &mut self.structinit_field_stack {
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
        stack.get_mut(index)
    }

    pub fn enter_structinit_stack(&mut self, value: StructInit) {
        match &mut self.structinit_stack {
            Some(v) => {
                v.push_back(value);
            },
            None => {
                let mut vec = VecDeque::new();
                vec.push_back(value);
                self.structinit_stack = Some(vec);
            }
        }
    }

    pub fn leave_structinit_stack(&mut self) -> Option<StructInit> {
        match &mut self.structinit_stack {
            Some(v) => {
                v.pop_back()
            },
            None => {
                None
            }
        }
    }

    pub fn get_structinit_stack_len(&self) -> usize {
        match &self.structinit_stack {
            Some(v) => {
                v.len()
            },
            None => {
                0
            }
        }
    }

    pub fn structinit_is_empty(&self) -> bool {
        if self.get_structinit_stack_len() == 0 {
            true
        } else {
            false
        }
    }

    pub fn get_current_mut_structinit_stack(&mut self) -> Option<&mut StructInit> {
        match &mut self.structinit_stack {
            Some(v) => {
                v.back_mut()
            },
            None => {
                None
            }
        }
    }

    pub fn get_structinit_stack_top_item_unchecked(&self) -> &StructInit {
        self.structinit_stack.as_ref().unwrap().front().unwrap()
    }

    pub fn enter_point_access(&mut self, v: PointAccess) {
        match &mut self.point_access {
            Some(pa) => {
                pa.push_back(v);
            },
            None => {
                let mut vec = VecDeque::new();
                vec.push_back(v);
                *&mut self.point_access = Some(vec);
            }
        }
    }

    pub fn leave_point_access(&mut self) {
        match &mut self.point_access {
            Some(pa) => {
                pa.pop_back();
                if pa.is_empty() {
                    *&mut self.point_access = None;
                    self.point_access_fullname = None;
                }
            },
            None => {
            }
        }
    }

    pub fn is_point_access(&self) -> bool {
        match &self.point_access {
            Some(_) => {
                true
            },
            None => {
                false
            }
        }
    }

    pub fn point_access_top_unchecked(&self) -> &PointAccess {
        match &self.point_access {
            Some(pa) => {
                pa.front().expect("should not append")
            },
            None => {
                panic!("should not happend");
            }
        }
    }

    pub fn point_access_current_unchecked(&self) -> &PointAccess {
        match &self.point_access {
            Some(pa) => {
                pa.back().expect("should not happend")
            },
            None => {
                panic!("should not happend");
            }
        }
    }

    pub fn append_point_access_fullname(&mut self, name: &str) {
        match &mut self.point_access_fullname {
            Some(n) => {
                n.push('.');
                n.push_str(name);
            },
            None => {
                *&mut self.point_access_fullname = Some(String::from(name));
            }
        }
    }

    pub fn get_point_access_fullname_unchecked(&self) -> &String {
        &self.point_access_fullname.as_ref().expect("should not happend")
    }

    pub fn enter_colon_colon_access(&mut self, v: ColonColonAccess) {
        self.colon_colon_access = Some(v);
    }

    pub fn leave_colon_colon_access(&mut self) {
        // *&mut self.colon_colon_access = None;
        self.colon_colon_access.take();
    }

    pub fn colon_coloin_access_current_unchecked(&self) -> &ColonColonAccess {
        self.colon_colon_access.as_ref().unwrap()
    }

    pub fn colon_colon_access_take_unwrap(&mut self) -> ColonColonAccess {
        self.colon_colon_access.take().unwrap()
    }

    pub fn is_colon_colon_access(&self) -> bool {
        self.colon_colon_access.is_some()
    }

    fn _new(start: usize, define_obj: DefineObject, scope_typ: ScopeType) -> Self {
        Self {
            scope_typ: scope_typ,
            define_obj: define_obj,
            address_dispatch: AddressDispatch::new_with_start(start),
            ref_counter: RefCounter::new(),
            vars: vars::Variants::new(),
            value_buffer: ValueBuffer::new(),
            func_return: None,
            func_call_stack: VecDeque::new(),
            func_param_addr_index: None,
            return_jumps: None,
            structinit_field_stack: None,
            structinit_stack: None,
            point_access: None,
            point_access_fullname: None,
            colon_colon_access: None
        }
    }

    pub fn new_with_addr_start(start: usize, scope_typ: ScopeType) -> Self {
        Scope::_new(start, DefineObject::new(HeapPtr::new_null()), scope_typ)
    }

    pub fn new_with_define_obj(define_obj: DefineObject, scope_typ: ScopeType) -> Self {
        Scope::_new(0, define_obj, scope_typ)
    }

    pub fn new(scope_typ: ScopeType) -> Self {
        Scope::_new(0, DefineObject::new(HeapPtr::new_null()), scope_typ)
    }
}

pub mod context;
pub mod vars;
