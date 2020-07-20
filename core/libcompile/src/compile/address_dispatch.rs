use crate::address::{Address, AddressType, AddressValue};
use libtype::instruction::{AddressKey};

pub struct AddressDispatch {
    pub addr_key: AddressKey,
    pub recycles: Vec<AddressValue>
}

impl AddressDispatch {
    fn alloc(&mut self, typ: AddressType, direction: Option<AddressValue>, is_add: bool) -> Address {
        let mut addr_key = AddressKey::default();
        if self.recycles.len() == 0 {
            addr_key = self.addr_key.clone();
            if is_add {
                self.addr_key.index += 1;
            }
        } else {
            addr_key = self.recycles.remove(0).addr();
        }
        let dir = match direction {
            Some(v) => {
                v
            },
            None => {
                AddressValue::new_invalid()
            }
        };
        Address::new(AddressValue::new(addr_key, typ), dir)
    }

    pub fn alloc_static(&mut self) -> Address {
        self.alloc(AddressType::Static, None, true)
    }

    pub fn alloc_stack(&mut self) -> Address {
        self.alloc(AddressType::Stack, None, true)
    }

    pub fn alloc_ref(&mut self, src: AddressValue) -> Address {
        self.alloc(AddressType::Ref, Some(src), true)
    }

    pub fn copy_from_ref(&mut self, src: AddressValue) -> Address {
        Address::new(src, AddressValue::new_invalid())
    }

    pub fn prepare_ref(&mut self, src: AddressValue) -> Address {
        self.alloc(AddressType::Ref, Some(src), false)
    }

    pub fn prepare_calc(&mut self, src: AddressValue) -> Address {
        self.alloc(AddressType::Calc, Some(src), false)
    }

    pub fn recycle_addr(&mut self, addr: AddressValue) {
        self.recycles.push(addr);
    }

    pub fn new() -> Self {
        Self {
            addr_key: AddressKey::default(),
            recycles: Vec::new()
        }
    }
}

