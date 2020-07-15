#[derive(Clone)]
pub struct Address {
    index: u64
}

impl Address {
    pub fn plus_one(&mut self) -> &Address {
        self.index += 1;
        self
    }

    pub fn new() -> Self {
        Self {
            index: 0
        }
    }
}

pub struct AddressDispatch {
    pub addr: Address
}

impl AddressDispatch {
    pub fn alloc(&mut self) -> Address {
        self.addr.plus_one().clone()
    }

    pub fn new() -> Self {
        Self {
            addr: Address{
                index: 0
            }
        }
    }
}

