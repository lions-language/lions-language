#[derive(Clone, Debug)]
pub enum AddressType {
    Ref,
    Static,
    New,
    Move,
    Invalid
}

#[derive(Clone, Debug)]
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
}

pub struct AddressDispatch {
    pub index: u64,
    pub recycles: Vec<u64>
}

impl AddressDispatch {
    fn alloc(&mut self, typ: AddressType, direction: Option<AddressValue>, is_add: bool) -> Address {
        let mut index = 0;
        if self.recycles.len() == 0 {
            index = self.index;
            if is_add {
                self.index += 1;
            }
        } else {
            index = self.recycles.remove(0);
        }
        let dir = match direction {
            Some(v) => {
                v
            },
            None => {
                AddressValue::new_invalid()
            }
        };
        Address {
            addr: AddressValue::new(index, typ),
            direction: dir
        }
    }

    pub fn alloc_static(&mut self) -> Address {
        self.alloc(AddressType::Static, None, true)
    }

    pub fn alloc_new(&mut self) -> Address {
        self.alloc(AddressType::New, None, true)
    }

    pub fn alloc_move(&mut self, src: AddressValue) -> Address {
        self.alloc(AddressType::Move, Some(src), true)
    }

    pub fn alloc_ref(&mut self, src: AddressValue) -> Address {
        self.alloc(AddressType::Ref, Some(src), true)
    }

    pub fn prepare_ref(&mut self, src: AddressValue) -> Address {
        self.alloc(AddressType::Ref, Some(src), false)
    }

    pub fn recycle_addr(&mut self, addr: u64) {
        self.recycles.push(addr);
    }

    pub fn new() -> Self {
        Self {
            index: 0,
            recycles: Vec::new()
        }
    }
}

