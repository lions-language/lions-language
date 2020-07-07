use libgrammar::token::{TokenValue};
use std::collections::{VecDeque};

pub struct ValueBuffer {
    buffer: VecDeque<TokenValue>
}

impl ValueBuffer {
    pub fn top_n_with_panic(&self, n: usize) -> &TokenValue {
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

    pub fn top_n(&self, n: usize) -> Option<&TokenValue> {
        if self.buffer.len() < n {
            return None;
        }
        let index = self.buffer.len() - n;
        self.buffer.get(index)
    }

    pub fn push(&mut self, value: TokenValue) {
        self.buffer.push_back(value);
    }

    pub fn new() -> Self {
        Self {
            buffer: VecDeque::new()
        }
    }
}
