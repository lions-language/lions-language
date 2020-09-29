use libcommon::ptr::{RefPtr, HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove, NewWithAll};
use libtype::function::FunctionStatement;
use crate::define_stream::{DefineItemObject};

pub enum DefineType {
    Function,
    Block
}

impl From<u8> for DefineType {
    fn from(v: u8) -> Self {
        match v {
            0 => {
                DefineType::Function
            },
            1 => {
                DefineType::Block
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl From<&u8> for DefineType {
    fn from(v: &u8) -> Self {
        match v {
            &0 => {
                DefineType::Function
            },
            &1 => {
                DefineType::Block
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

impl Into<u8> for DefineType {
    fn into(self) -> u8 {
        match self {
            DefineType::Function => {
                0
            },
            DefineType::Block => {
                1
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

#[derive(Debug)]
pub struct FunctionDefineObject(HeapPtr);

#[derive(FieldGet, FieldGetClone, FieldGetMove)]
pub struct FunctionDefine {
    statement: FunctionStatement,
    define_item: DefineItemObject
}
/*
#[derive(FieldGet)]
pub struct FunctionDefine {
    start_pos: usize,
    length: usize,
    statement: FunctionStatement,
    to_be_filled: to_be_filled::function::FuncToBeFilled,
    define_item: RefPtr
}
*/

#[derive(Debug)]
pub struct BlockDefineObject(HeapPtr);

#[derive(FieldGet)]
pub struct BlockDefine {
    define_item: DefineItemObject
}

/*
 * 用来保存 FunctionDefine 对象
 * */
#[derive(Debug, FieldGet, FieldGetClone, Clone)]
pub struct DefineObject {
    ptr: HeapPtr
}

impl Default for DefineObject {
    fn default() -> Self {
        Self {
            ptr: HeapPtr::new_null()
        }
    }
}

impl DefineObject {
    pub fn get<T>(&self) -> Box<T> {
        self.ptr.pop::<T>()
    }

    pub fn restore<T>(&self, v: Box<T>) {
        self.ptr.push::<T>(v);
    }

    pub fn new(ptr: HeapPtr) -> Self {
        Self {
            ptr: ptr
        }
    }
}

mod function;
mod block;
mod to_be_filled;
