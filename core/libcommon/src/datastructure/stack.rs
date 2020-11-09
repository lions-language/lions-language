use std::collections::VecDeque;

pub struct Stack<T> {
    datas: VecDeque<T>
}

impl<T> Stack<T> {
    pub fn push(&mut self, data: T) {
        self.datas.push_back(data);
    }

    pub fn top_ref(&self) -> Option<&T> {
        self.datas.back()
    }

    pub fn top_ref_unchecked(&self) -> &T {
        self.datas.back().expect("should not happend: stack top_ref is empty")
    }

    pub fn top_mut(&mut self) -> Option<&mut T> {
        self.datas.back_mut()
    }

    pub fn top_mut_unchecked(&mut self) -> &mut T {
        self.datas.back_mut().expect("should not happend: stack top_mut is empty")
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

