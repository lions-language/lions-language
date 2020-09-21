use crate::address::{Address};
use libtype::{AddressKey, AddressValue, AddressType};
use std::collections::{HashSet};

pub struct AddressDispatch {
    pub addr_key: AddressKey,
    /*
     * TODO
     *  将回收机制去掉, 如果存在回收机制, 当前作用域将无法使用地址进行唯一标识
     *  那么将导致检测地址有效性出现错误
     * */
    pub recycles: Vec<AddressValue>,
    used_addr_index: HashSet<usize>,
    index: usize
}

impl AddressDispatch {
    pub fn alloc(&mut self, typ: AddressType
        , scope: usize, length: usize) -> Address {
        let addr_key = AddressKey::new_with_all(self.index as u64, 0, 0, scope, length);
        /*
         * length + 1 => 本身加length
         * */
        self.used_addr_index.insert(self.index as usize);
        self.index += 1;
        for _ in 0..length {
            self.used_addr_index.insert(self.index as usize);
            self.index += 1;
        }
        Address::new(AddressValue::new(typ, addr_key))
        /*
        if self.recycles.len() == 0 {
            // println!("from recycles");
            let addr_key = AddressKey::new_with_scope_single(self.index, scope);
            self.used_addr_index.insert(self.index as usize);
            self.index += 1;
            Address::new(AddressValue::new(typ, addr_key))
        } else {
            // println!("from new");
            let mut addr_key = self.recycles.remove(0).addr();
            *addr_key.scope_mut() = scope;
            self.used_addr_index.insert(addr_key.index_clone() as usize);
            Address::new(AddressValue::new(typ, addr_key))
        }
        // println!("{:?}", &addr_key);
        */
    }

    /*
    pub fn alloc_with_index(&mut self, typ: AddressType
        , index: usize, scope: usize, length: usize) -> Address {
        let addr_key = AddressKey::new_with_all(index as u64, 0, 0, scope, length);
        // println!("use: {}", index);
        self.used_addr_index.insert(index);
        self.index = index + 1;
        for _ in 0..(length+1) {
            self.used_addr_index.insert(index);
            self.index = index + 1;
        }
        Address::new(AddressValue::new(typ, addr_key))
    }
    */

    pub fn update_addr_index(&mut self, index: usize) {
        self.index = index;
    }

    pub fn use_addr(&mut self, addr: &AddressKey) {
        self.used_addr_index.insert(addr.index_clone() as usize);
    }

    pub fn alloc_continuous(&mut self, length: usize) -> usize {
        let start = self.index;
        for i in 0..length {
            self.used_addr_index.insert(i+start);
        }
        self.index += length;
        start as usize
    }

    pub fn addr_is_valid(&self, addr: &AddressValue) -> bool {
        match &addr.typ_ref() {
            AddressType::Static => {
                return true;
            },
            _ => {}
        }
        // println!("{:?}", self.used_addr_index);
        match self.used_addr_index.get(&(addr.addr_ref().index_clone() as usize)) {
            Some(_) => {
                // println!("{:?}", addr);
                true
            },
            None => {
                false
            }
        }
    }

    pub fn next_new_addr_index(&self) -> usize {
        self.index as usize
    }

    pub fn alloc_static(&mut self, scope: usize, length: usize) -> Address {
        self.alloc(AddressType::Static, scope, length)
    }

    pub fn alloc_stack(&mut self, scope: usize, length: usize) -> Address {
        self.alloc(AddressType::Stack, scope, length)
    }

    pub fn recycle_addr(&mut self, addr: AddressValue) {
        self.used_addr_index.remove(&(addr.addr_ref().index_clone() as usize));
        self.recycles.push(addr);
    }

    pub fn new_with_start(start: usize) -> Self {
        Self {
            addr_key: AddressKey::new_single(start as u64),
            recycles: Vec::new(),
            used_addr_index: HashSet::new(),
            index: 0
        }
    }

    pub fn new() -> Self {
        AddressDispatch::new_with_start(0)
    }
}

