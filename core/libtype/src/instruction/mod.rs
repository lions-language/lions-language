use libcommon::optcode;
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Hash, Eq, Default)]
pub struct AddressKey {
    pub module_index: u64,
    pub index: u64
}

impl AddressKey {
    pub fn new(module_index: u64, index: u64) -> Self {
        Self {
            module_index: module_index,
            index: index
        }
    }   

    pub fn new_without_module(index: u64) -> Self {
        Self {
            module_index: 0,
            index: index
        }
    }   
}

/*
#[derive(Debug)]
pub enum AddressValue {
    Static(u64),
    Stack(u64),
    Calc(u64)
}
*/

#[derive(Debug)]
pub enum AddressType {
    Static,
    Stack,
}

#[derive(Debug)]
pub struct AddressValue {
    typ: AddressType,
    addr: AddressKey
}

impl AddressValue {
    pub fn typ_ref(&self) -> &AddressType {
        &self.typ
    }

    pub fn addr_ref(&self) -> &AddressKey {
        &self.addr
    }

    pub fn addr_clone(&self) -> AddressKey {
        self.addr.clone()
    }

    pub fn addr(self) -> AddressKey {
        self.addr
    }

    pub fn new(typ: AddressType, addr: AddressKey) -> Self {
        Self {
            typ: typ,
            addr: addr
        }
    }
}

#[derive(Debug)]
pub struct CallPrimevalFunction {
    pub opt: optcode::OptCode,
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
    CallPrimevalFunction(CallPrimevalFunction)
}
