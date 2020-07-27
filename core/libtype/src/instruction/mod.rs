use libcommon::optcode;
use libcommon::address::{FunctionAddress};
use crate::{AddressValue, AddressKey};

#[derive(Debug)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
    pub return_addr: AddressValue
}

#[derive(Debug)]
pub struct CallFunction {
    pub define_addr: FunctionAddress,
    pub return_addr: AddressValue
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Uint8Static {
    pub addr: AddressKey,
    pub value: u8
}

#[derive(Debug)]
pub struct Uint16Static {
    pub addr: AddressKey,
    pub value: u16
}

#[derive(Debug)]
pub struct Uint32Static {
    pub addr: AddressKey,
    pub value: u32
}

/*
 * 指令
 * */
#[derive(Debug)]
pub enum Instruction {
    LoadUint8Const(Uint8Static),
    LoadUint16Const(Uint16Static),
    LoadUint32Const(Uint32Static),
    LoadVariant(VariantValue),
    CallPrimevalFunction(CallPrimevalFunction),
    CallFunction(CallFunction)
}
