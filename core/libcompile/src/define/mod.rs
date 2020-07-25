use libcommon::ptr::RefPtr;

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

pub struct FunctionDefine {
}

impl FunctionDefine {
    pub fn new() -> Self {
        Self {
        }
    }
}

pub type DefineObject = RefPtr;

mod function;
