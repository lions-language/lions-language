use std::collections::VecDeque;

pub enum StackData {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64)
}

pub struct Stack {
    deque: VecDeque<StackData>
}

impl Stack {
    pub fn push(&mut self, data: StackData) {
        self.deque.push_back(data);
    }

    pub fn pop_unchecked(&mut self) -> StackData {
        self.deque.pop_back().expect("")
    }

    pub fn pop(&mut self) -> Option<StackData> {
        self.deque.pop_back()
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn new() -> Self {
        Self {
            deque: VecDeque::new()
        }
    }
}
