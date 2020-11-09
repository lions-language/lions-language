use std::collections::VecDeque;

pub struct Stack<T> {
    datas: VecDeque<T>
}

impl<T> Stack<T> {
    pub fn push(&mut self, data: T) {
        self.datas.push_back(data);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.datas.pop_back()
    }

    pub fn new() -> Self {
        Self {
            datas: VecDeque::new()
        }
    }
}

