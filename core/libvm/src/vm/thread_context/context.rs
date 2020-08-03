use super::{ThreadScope};
use std::collections::VecDeque;

pub struct ThreadContext {
    scopes: VecDeque<ThreadScope>
}

impl ThreadContext {
    pub fn enter(&mut self) {
        self.scopes.push_back(ThreadScope::new());
    }

    pub fn leave(&mut self) {
        self.scopes.pop_back();
    }
    
    pub fn current_mut_unchecked(&mut self) -> &mut ThreadScope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unchecked(&self) -> &ThreadScope {
        self.scopes.back().expect("should not happend")
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}
