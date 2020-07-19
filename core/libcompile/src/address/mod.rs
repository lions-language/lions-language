use libtype::instruction;
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
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

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum AddressType {
    Ref,
    Static,
    Stack,
    Calc,
    Invalid
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct AddressValue {
    addr: u64,
    typ: AddressType
}

impl AddressValue {
    pub fn addr_ref(&self) -> &u64 {
        &self.addr
    }

    pub fn addr(&self) -> u64 {
        self.addr
    }

    pub fn typ_ref(&self) -> &AddressType {
        &self.typ
    }

    pub fn typ(&self) -> AddressType {
        self.typ.clone()
    }

    pub fn new(addr: u64, typ: AddressType) -> Self {
        Self {
            addr: addr,
            typ: typ
        }
    }

    pub fn new_invalid() -> Self {
        Self {
            addr: 0,
            typ: AddressType::Invalid
        }
    }

    pub fn to_instruction_value(&self) -> instruction::AddressValue {
        match self.typ {
            AddressType::Static => {
                instruction::AddressValue::Static(self.addr)
            },
            AddressType::Stack => {
                instruction::AddressValue::Stack(self.addr)
            },
            AddressType::Calc => {
                instruction::AddressValue::Calc(self.addr)
            },
            _ => {
                /*
                 * compile 会将所有的 Ref 都转换为实际的地址
                 * */
                panic!("should not happend: {:?}", self.typ);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Address {
    /*
     * 本身地址
     * */
    addr: AddressValue,
    /*
     * 指向的地址
     * */
    direction: AddressValue
}

impl Address {
    pub fn addr_ref(&self) -> &AddressValue {
        &self.addr
    }

    pub fn direction_ref(&self) -> &AddressValue {
        &self.direction
    }

    pub fn addr(&self) -> AddressValue {
        self.addr.clone()
    }

    pub fn direction(&self) -> AddressValue {
        self.direction.clone()
    }

    pub fn new_invalid() -> Address {
        Address {
            addr: AddressValue::new_invalid(),
            direction: AddressValue::new_invalid()
        }
    }

/*
    TODO: 处理 Ref 的情况
    pub fn to_instruction_value(&self) -> instruction::AddressValue {
        match self.typ {
            AddressType::Static => {
                instruction::AddressValue::Static(self.addr)
            },
            AddressType::Stack => {
                instruction::AddressValue::Stack(self.addr)
            },
            AddressType::Calc => {
                instruction::AddressValue::Calc(self.addr)
            },
            _ => {
                /*
                 * compile 会将所有的 Ref 都转换为实际的地址
                 * */
                panic!("should not happend: {:?}", self.typ);
            }
        }
    }
*/

    pub fn new(addr: AddressValue, direction: AddressValue) -> Self {
        Self {
            addr: addr,
            direction: direction
        }
    }
}


