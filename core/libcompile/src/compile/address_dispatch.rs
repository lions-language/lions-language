use crate::address::{Address};
use libtype::{AddressKey, AddressValue, AddressType};

pub struct AddressDispatch {
    pub addr_key: AddressKey,
    pub recycles: Vec<AddressValue>,
    index: u64
}

impl AddressDispatch {
    pub fn alloc(&mut self, typ: AddressType) -> Address {
        if self.recycles.len() == 0 {
            let addr_key = AddressKey::new(self.index);
            self.index += 1;
            Address::new(AddressValue::new(typ, addr_key))
        } else {
            let addr_key = self.recycles.remove(0).addr();
            Address::new(AddressValue::new(typ, addr_key))
        }
        // println!("{:?}", &addr_key);
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

    pub fn new() -> Self {
        Self {
            addr_key: AddressKey::new(0),
            recycles: Vec::new(),
            index: 0
        }
    }
}

