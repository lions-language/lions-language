use libcommon::ptr::RefPtr;
use libmacro::{FieldGet, FieldGetClone};

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

#[derive(FieldGet, FieldGetClone)]
pub struct FunctionDefine {
    start_pos: usize,
    length: usize
}

#[derive(FieldGet, FieldGetClone)]
pub struct DefineObject {
    ptr: RefPtr,
    is_exist_undefine: bool
}

impl DefineObject {
    pub fn set_undefine(&mut self) {
        self.is_exist_undefine = true;
    }

    pub fn new(ptr: RefPtr) -> Self {
        Self {
            ptr: ptr,
            is_exist_undefine: false
        }
    }
}

mod function;
