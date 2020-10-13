use libmacro::{FieldGet, FieldGetClone
    , FieldGetMove};

#[derive(Debug, Clone
    , FieldGet
    , FieldGetClone
    , FieldGetMove)]
pub struct FunctionAddrValue {
    valid: bool,
    index: usize,
    length: usize
}

impl FunctionAddrValue {
    pub fn is_valid(&self) -> bool {
        self.valid.clone()
    }

    pub fn new_valid(index: usize, length: usize) -> Self {
        FunctionAddrValue::new(true, index, length)
    }

    pub fn new_invalid() -> Self {
        FunctionAddrValue::new(false, 0, 0)
    }

    pub fn new(valid: bool, index: usize, length: usize) -> Self {
        Self {
            valid: valid,
            index: index,
            length: length
        }
    }
}

impl Default for FunctionAddrValue {
    fn default() -> Self {
        FunctionAddrValue::new_invalid()
    }
}

#[derive(Debug, Clone)]
pub enum FunctionAddress {
    ReferencesDefine(FunctionAddrValue),
    Define(FunctionAddrValue)
}

