use libcommon::optcode;
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct AddressKey {
    pub module_index: u64,
    pub index: u64
}

#[derive(Debug)]
pub enum AddressValue {
    Static(u64),
    Stack(u64),
    Calc(u64)
}

/*
#[derive(Debug)]
pub enum AddressType {
    Static,
    Stack,
    Calc
}

#[derive(Debug)]
pub struct AddressValue {
    typ: AddressType,
    addr_key: AddressKey
}
*/

#[derive(Debug)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
    pub return_addr: AddressValue
}

#[derive(Debug)]
pub struct VariantValue {
    pub addr: AddressValue,
    pub direction: AddressValue
}

impl VariantValue {
    pub fn new(addr: AddressValue, direction: AddressValue) -> Self {
        Self {
            addr: addr,
            direction: direction
        }
    }
}

#[derive(Debug)]
pub struct Uint8Static {
    pub addr: u64,
    pub value: u8
}

#[derive(Debug)]
pub struct Uint16Static {
    pub addr: u64,
    pub value: u16
}

#[derive(Debug)]
pub struct Uint32Static {
    pub addr: u64,
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
    CallPrimevalFunction(CallPrimevalFunction)
}
