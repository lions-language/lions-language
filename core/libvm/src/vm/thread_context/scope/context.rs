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
    
    pub fn current_mut_unchecked(&mut self) -> &mut Scope {
        self.scopes.back_mut().expect("should not happend")
    }

    pub fn current_unchecked(&self) -> &Scope {
        self.scopes.back().expect("should not happend")
    }

    pub fn last_one_unchecked(&self) -> &Scope {
        /*
         * 获取前一个作用域
         * */
        self.last_n_unchecked(1)
    }

    pub fn last_one_mut_unchecked(&mut self) -> &mut Scope {
        self.last_n_mut_unchecked(1)
    }

    pub fn last_n_unchecked(&self, n: usize) -> &Scope {
        // println!("len: {}, n: {}", self.scopes.len(), n);
        let index = self.scopes.len() - 1 - n;
        self.scopes.get(index).expect(&format!("len: {}, index: {}", self.scopes.len(), index))
    }

    pub fn last_n_mut_unchecked(&mut self, n: usize) -> &mut Scope {
        let len = self.scopes.len();
        let index = len - 1 - n;
        self.scopes.get_mut(index).expect(&format!("len: {}, index: {}", len, index))
    }

    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}

