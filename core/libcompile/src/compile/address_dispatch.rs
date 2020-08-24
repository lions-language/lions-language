use crate::address::{Address};
use libtype::{AddressKey, AddressValue, AddressType};

pub struct AddressDispatch {
    pub addr_key: AddressKey,
    pub recycles: Vec<AddressValue>,
    index: u64
}

impl AddressDispatch {
    pub fn alloc(&mut self, typ: AddressType
        , scope: usize) -> Address {
        if self.recycles.len() == 0 {
            // println!("from recycles");
            let addr_key = AddressKey::new_with_scope(self.index, scope);
            self.index += 1;
            Address::new(AddressValue::new(typ, addr_key))
        } else {
            // println!("from new");
            let mut addr_key = self.recycles.remove(0).addr();
            *addr_key.scope_mut() = scope;
            Address::new(AddressValue::new(typ, addr_key))
        }
        // println!("{:?}", &addr_key);
    }

    pub fn alloc_static(&mut self, scope: usize) -> Address {
        self.alloc(AddressType::Static, scope)
    }

    pub fn alloc_stack(&mut self, scope: usize) -> Address {
        self.alloc(AddressType::Stack, scope)
    }

    pub fn recycle_addr(&mut self, addr: AddressValue) {
        self.recycles.push(addr);
    }

    pub fn new_with_start(start: usize) -> Self {
        Self {
            addr_key: AddressKey::new(start as u64),
            recycles: Vec::new(),
            index: 0
        }
    }

    pub fn new() -> Self {
        AddressDispatch::new_with_start(0)
    }
}

