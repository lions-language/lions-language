use crate::address::{Address};
use libtype::{AddressKey, AddressValue, AddressType};

pub struct AddressDispatch {
    pub addr_key: AddressKey,
    pub recycles: Vec<AddressValue>
}

impl AddressDispatch {
    fn alloc(&mut self, typ: AddressType) -> Address {
        let mut addr_key = AddressKey::default();
        if self.recycles.len() == 0 {
            addr_key = self.addr_key.clone();
            self.addr_key.index += 1;
        } else {
            addr_key = self.recycles.remove(0).addr();
        }
        Address::new(AddressValue::new(typ, addr_key))
    }

    pub fn alloc_static(&mut self) -> Address {
        self.alloc(AddressType::Static)
    }

    pub fn alloc_stack(&mut self) -> Address {
        self.alloc(AddressType::Stack)
    }

    pub fn recycle_addr(&mut self, addr: AddressValue) {
        self.recycles.push(addr);
    }

    pub fn new(module_index: u64) -> Self {
        Self {
            addr_key: AddressKey::new(module_index, 0),
            recycles: Vec::new()
        }
    }
}

