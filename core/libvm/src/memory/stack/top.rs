use super::TopStack;
use std::collections::VecDeque;

impl<T> TopStack<T> {
    pub fn push(&mut self, d: T) {
        self.datas.push_back(d);
    }

    pub fn pop_uncheck(&mut self) -> T {
        self.datas.pop_back().unwrap()
    }

    pub fn new() -> Self {
        Self {
            datas: VecDeque::new()
        }
    }
}

