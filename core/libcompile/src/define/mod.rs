use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetClone};
use libtype::function::FunctionStatement;
use crate::define_stream::DefineStream;

pub enum DefineType {
    Function
}

impl From<u8> for DefineType {
    fn from(v: u8) -> Self {
        match v {
            0 => {
                DefineType::Function
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
            _ => {
                unimplemented!();
            }
        }
    }
}

#[derive(FieldGet)]
pub struct FunctionDefine {
    start_pos: usize,
    length: usize,
    statement: FunctionStatement,
    to_be_filled: to_be_filled::function::FuncToBeFilled,
    define_stream: RefPtr
}

/*
 * 用来保存 FunctionDefine 对象
 * */
#[derive(FieldGet, FieldGetClone, Clone)]
pub struct DefineObject {
    ptr: RefPtr
}

impl Default for DefineObject {
    fn default() -> Self {
        Self {
            ptr: RefPtr::new_null()
        }
    }
}

impl DefineObject {
    pub fn new(ptr: RefPtr) -> Self {
        Self {
            ptr: ptr
        }
    }
}

mod function;
mod to_be_filled;
