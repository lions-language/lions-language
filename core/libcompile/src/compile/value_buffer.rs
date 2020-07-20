use libtype::Type;
use crate::address::{Address};
use std::collections::{VecDeque};

pub struct Item {
    pub typ: Type,
    pub addr: Address
}

pub struct ValueBuffer {
    buffer: VecDeque<Item>
}

impl ValueBuffer {
    pub fn top_n_with_panic(&self, n: usize) -> &Item {
        /*
         * 获取 top 往前数的 第n个值
         * 如果找不到就抛出异常
         * */
        match self.top_n(n) {
            Some(v) => {
                v
            },
            None => {
                panic!("top n panic");
            }
        }
    }

    pub fn top_n(&self, n: usize) -> Option<&Item> {
        if self.buffer.len() < n {
            return None;
        }
        let index = self.buffer.len() - n;
        self.buffer.get(index)
    }

    pub fn take_top(&mut self) -> Item {
        match self.buffer.pop_back() {
            Some(t) => {
                t
            },
            None => {
                panic!("queue is empty");
            }
        }
    }

    pub fn push_with_addr(&mut self, typ: Type, addr: Address) {
        self.buffer.push_back(Item {
            typ: typ,
            addr: addr
        });
    }
    
    pub fn push(&mut self, typ: Type) {
        self.buffer.push_back(Item {
            typ: typ,
            addr: Address::default()
        });
    }

    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new()
        }
    }
}
