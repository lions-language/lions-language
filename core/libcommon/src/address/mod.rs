use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove};

#[derive(Debug, Clone, FieldGet
    , FieldGetClone
    , FieldGetMove)]
pub struct FunctionAddrValue {
    index: usize,
    length: usize
}

impl FunctionAddrValue {
    pub fn new(index: usize, length: usize) -> Self {
        Self {
            index: index,
            length: length
        }
    }
}

#[derive(Debug, Clone)]
pub enum FunctionAddress {
    ReferencesDefine(FunctionAddrValue),
    Define(FunctionAddrValue)
}

