use super::{Scope};
use std::collections::VecDeque;

pub struct ScopeContext {
    scopes: VecDeque<Scope>
}

impl ScopeContext {
    pub fn enter(&mut self) {
        self.scopes.push_back(Scope::new());
    }

    pub fn leave(&mut self) {
        self.scopes.pop_back();
    }
    
    pub fn current_mut_unchecked(&mut self) -> &mut Scope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unchecked(&self) -> &Scope {
        self.scopes.back().expect("should not happend")
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}

