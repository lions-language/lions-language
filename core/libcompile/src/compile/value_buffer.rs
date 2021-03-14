use libtype::{Type, TypeAttrubute};
use libtype::package::{PackageStr};
use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove};
use libcommon::ptr::RefPtr;
use crate::address::{Address};
use std::collections::{VecDeque};

#[derive(Debug, Clone)]
pub enum ValueBufferItemContext {
    Variant(RefPtr),
    Structure,
    Interface,
    Null
}

#[derive(Debug, FieldGet, FieldGetClone
    , FieldGetMove, Clone)]
pub struct ValueBufferItem {
    pub typ: Type,
    pub addr: Address,
    pub typ_attr: TypeAttrubute,
    pub package_str: PackageStr,
    pub context: ValueBufferItemContext
}

pub struct ValueBuffer {
    buffer: VecDeque<ValueBufferItem>
}

impl ValueBuffer {
    pub fn top_n_with_panic(&self, n: usize) -> &ValueBufferItem {
        /*
         * 获取 top 往前数的 第n个值
         * 如果找不到就抛出异常
         * */
        match self.top_n(n) {
            Some(v) => {
                v
            },
            None => {
                panic!("top n panic");
            }
        }
    }

    pub fn top_n(&self, n: usize) -> Option<&ValueBufferItem> {
        if self.buffer.len() < n {
            return None;
        }
        let index = self.buffer.len() - n;
        self.buffer.get(index)
    }

    pub fn take_top(&mut self) -> ValueBufferItem {
        match self.buffer.pop_back() {
            Some(t) => {
                t
            },
            None => {
                panic!("queue is empty");
            }
        }
    }

    pub fn push_with_addr(&mut self, typ: Type, addr: Address) {
        self.buffer.push_back(ValueBufferItem {
            typ: typ,
            addr: addr,
            typ_attr: TypeAttrubute::Move,
            package_str: PackageStr::Empty,
            context: ValueBufferItemContext::Null
        });
    }

    pub fn push_with_addr_typattr(&mut self, typ: Type, addr: Address
        , typ_attr: TypeAttrubute) {
        self.buffer.push_back(ValueBufferItem {
            typ: typ,
            addr: addr,
            typ_attr: typ_attr,
            package_str: PackageStr::Empty,
            context: ValueBufferItemContext::Null
        });
    }

    pub fn push_with_addr_context(&mut self, typ: Type, addr: Address
        , context: ValueBufferItemContext) {
        self.buffer.push_back(ValueBufferItem {
            typ: typ,
            addr: addr,
            typ_attr: TypeAttrubute::Move,
            package_str: PackageStr::Empty,
            context: context
        });
    }

    pub fn push_with_addr_context_typattr(&mut self, typ: Type, addr: Address
        , context: ValueBufferItemContext, typ_attr: TypeAttrubute) {
        self.buffer.push_back(ValueBufferItem {
            typ: typ,
            addr: addr,
            typ_attr: typ_attr,
            package_str: PackageStr::Empty,
            context: context
        });
    }
    
    pub fn push(&mut self, typ: Type) {
        self.push_with_addr(typ, Address::default());
    }

    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new()
        }
    }
}
