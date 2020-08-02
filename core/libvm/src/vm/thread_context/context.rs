use super::{ThreadScope};
use std::collections::VecDeque;

pub struct ThreadContext {
    scopes: VecDeque<ThreadScope>
}

impl ThreadContext {
    pub fn new() -> Self {
        Self {
            scopes: VecDeque::new()
        }
    }
}
