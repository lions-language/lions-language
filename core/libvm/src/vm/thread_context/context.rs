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

    pub fn last_n_is_valid(&self, scope: usize) -> bool {
        let len = self.scopes.len();
        if len == 0 {
            return false;
        }
        if self.scopes.len() - 1 < scope {
            false
        } else {
            true
        }
    }

    pub fn enter_thread_scope(&mut self) {
        // println!("enter scope");
        self.current_mut_unchecked().scope_context_mut().enter();
    }

    pub fn leave_thread_scope(&mut self) {
        // println!("leave scope");
        self.current_mut_unchecked().scope_context_mut().leave();
    }
    
    pub fn current_mut_unchecked(&mut self) -> &mut ThreadScope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unchecked(&self) -> &ThreadScope {
        self.scopes.back().expect("should not happend")
    }

    pub fn new_with_first() -> Self {
        ThreadContext::new_with_scope(ThreadScope::new())
    }

    pub fn new_with_scope(scope: ThreadScope) -> Self {
        let mut scopes = VecDeque::new();
        scopes.push_back(scope);
        Self {
            scopes: scopes
        }
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}
