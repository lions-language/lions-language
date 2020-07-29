use libcommon::optcode;
use libcommon::address::{FunctionAddress};
use libmacro::{FieldGet};
use crate::{AddressValue, AddressKey};
use crate::package::PackageStr;

#[derive(Debug, Clone)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
    pub return_addr: AddressValue
}

#[derive(Debug, FieldGet, Clone)]
pub struct CallFunction {
    pub package_str: PackageStr,
    pub define_addr: FunctionAddress,
    pub return_addr: AddressValue
}

#[derive(Debug, Clone)]
pub struct VariantValue {
    pub direction: AddressValue
}

impl VariantValue {
    pub fn new(direction: AddressValue) -> Self {
        Self {
            direction: direction
        }
    }
}

#[derive(Debug, Clone)]
pub struct Uint8Static {
    pub addr: AddressKey,
    pub value: u8
}

#[derive(Debug, Clone)]
pub struct Uint16Static {
    pub addr: AddressKey,
    pub value: u16
}

#[derive(Debug, Clone)]
pub struct Uint32Static {
    pub addr: AddressKey,
    pub value: u32
}

/*
 * 指令
 * */
#[derive(Debug, Clone)]
pub enum Instruction {
    LoadUint8Const(Uint8Static),
    LoadUint16Const(Uint16Static),
    LoadUint32Const(Uint32Static),
    LoadVariant(VariantValue),
    CallPrimevalFunction(CallPrimevalFunction),
    CallFunction(CallFunction),
    Invalid
}
