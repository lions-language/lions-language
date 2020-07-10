use libtype::Type;
use std::collections::{VecDeque};

pub struct ValueBuffer {
    buffer: VecDeque<Type>
}

impl ValueBuffer {
    pub fn top_n_with_panic(&self, n: usize) -> &Type {
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

    pub fn top_n(&self, n: usize) -> Option<&Type> {
        if self.buffer.len() < n {
            return None;
        }
        let index = self.buffer.len() - n;
        self.buffer.get(index)
    }

    pub fn take_top(&mut self) -> Type {
        match self.buffer.pop_back() {
            Some(t) => {
                t
            },
            None => {
                panic!("queue is empty");
            }
        }
    }

    pub fn push(&mut self, typ: Type) {
        self.buffer.push_back(typ);
    }

    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new()
        }
    }
}
