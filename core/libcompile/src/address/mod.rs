use libtype::instruction::{self, AddressKey};
use std::cmp::{PartialEq, Eq};
use std::hash::Hash;

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum AddressType {
    Static,
    Stack,
    Invalid
}

impl Default for AddressType {
    fn default() -> Self {
        AddressType::Invalid
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq, Default)]
pub struct AddressValue {
    addr: AddressKey,
    typ: AddressType
}

impl AddressValue {
    pub fn addr_ref(&self) -> &AddressKey {
        &self.addr
    }

    pub fn addr(&self) -> AddressKey {
        self.addr.clone()
    }

    pub fn typ_ref(&self) -> &AddressType {
        &self.typ
    }

    pub fn typ(&self) -> AddressType {
        self.typ.clone()
    }

    pub fn new(addr: AddressKey, typ: AddressType) -> Self {
        Self {
            addr: addr,
            typ: typ
        }
    }

    pub fn new_invalid() -> Self {
        Self {
            addr: AddressKey::default(),
            typ: AddressType::Invalid
        }
    }

    pub fn to_instruction_value(&self) -> instruction::AddressValue {
        // println!("{:?}", &self.typ);
        match &self.typ {
            AddressType::Static => {
                instruction::AddressValue::new(
                    instruction::AddressType::Static
                    , self.addr())
            },
            AddressType::Stack => {
                instruction::AddressValue::new(
                    instruction::AddressType::Stack
                    , self.addr())
            },
            /*
            AddressType::Calc => {
                instruction::AddressValue::new(
                    instruction::AddressType::Calc
                    , self.addr())
            },
            */
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
    addr: AddressValue
}

impl Address {
    pub fn addr_ref(&self) -> &AddressValue {
        &self.addr
    }

    pub fn addr_clone(&self) -> AddressValue {
        self.addr.clone()
    }

    pub fn addr(self) -> AddressValue {
        self.addr
    }

    pub fn new_invalid() -> Address {
        Address {
            addr: AddressValue::new_invalid()
        }
    }

    /*
    pub fn to_instruction_value(&self) -> instruction::AddressValue {
        match &self.addr_ref().typ_ref() {
            AddressType::Ref
            | AddressType::Calc => {
                self.direction_ref().to_instruction_value()
            },
            AddressType::Invalid => {
                /*
                 * compile 会将所有的 Ref 都转换为实际的地址
                 * */
                panic!("should not happend: {:?}", self.addr_ref().typ_ref());
            },
            _ => {
                self.addr_ref().to_instruction_value()
            }
        }
    }
    */

    pub fn new(addr: AddressValue) -> Self {
        Self {
            addr: addr
        }
    }
}

/*
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

    pub fn to_instruction_value(&self) -> instruction::AddressValue {
        match &self.addr_ref().typ_ref() {
            AddressType::Ref
            | AddressType::Calc => {
                self.direction_ref().to_instruction_value()
            },
            AddressType::Invalid => {
                /*
                 * compile 会将所有的 Ref 都转换为实际的地址
                 * */
                panic!("should not happend: {:?}", self.addr_ref().typ_ref());
            },
            _ => {
                self.addr_ref().to_instruction_value()
            }
        }
    }

    pub fn new(addr: AddressValue, direction: AddressValue) -> Self {
        Self {
            addr: addr,
            direction: direction
        }
    }
}
*/


