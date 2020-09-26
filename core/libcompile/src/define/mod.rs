use libcommon::ptr::{RefPtr, HeapPtr};
use libmacro::{FieldGet, FieldGetClone};
use libtype::function::FunctionStatement;
use crate::define_stream::{DefineItemObject};

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

pub struct FunctionDefineObject(HeapPtr);

impl FunctionDefineObject {
    pub fn new(define: FunctionDefine) -> Self {
        Self(HeapPtr::alloc(define))
    }

    pub fn get(&self) -> Box<FunctionDefine> {
        self.0.pop::<FunctionDefine>()
    }

    pub fn restore(&self, v: Box<FunctionDefine>) {
        self.0.push::<FunctionDefine>(v)
    }

    pub fn free(&self) {
        self.0.free::<FunctionDefine>();
    }

    pub fn ptr_clone(&self) -> HeapPtr {
        self.0.clone()
    }
}

#[derive(FieldGet)]
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

/*
 * 用来保存 FunctionDefine 对象
 * */
#[derive(FieldGet, FieldGetClone, Clone)]
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
mod to_be_filled;
