use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetClone};
use libtype::function::FunctionStatement;

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
    statement: FunctionStatement
}

#[derive(FieldGet, FieldGetClone)]
pub struct DefineObject {
    ptr: RefPtr
}

impl DefineObject {
    pub fn new(ptr: RefPtr) -> Self {
        Self {
            ptr: ptr
        }
    }
}

mod function;
