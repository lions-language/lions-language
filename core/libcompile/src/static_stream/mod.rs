use libtype::{Data, AddressKey};
use libmacro::{FieldGet};
use std::collections::VecDeque;

#[derive(FieldGet)]
pub struct StaticStream {
    datas: VecDeque<Data>
}

impl StaticStream {
    pub fn push(&mut self, data: Data) {
        self.datas.push_back(data);
    }

    pub fn data_ref_unchecked(&self, addr_key: &AddressKey) -> &Data {
        self.datas.get(addr_key.index_clone() as usize).expect("should not happend")
    }

    pub fn length(&self) -> usize {
        self.datas.len()
    }

    pub fn new() -> Self {
        Self {
            datas: VecDeque::new()
        }
    }
}

