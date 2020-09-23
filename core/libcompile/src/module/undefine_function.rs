use super::{UndefineFunction, UndefFuncs};
use std::collections::{HashMap};

impl UndefineFunction {
    pub fn new() -> Self {
        Self {
        }
    }
}

impl UndefFuncs {
    pub fn new() -> Self {
        Self {
            funcs: HashMap::new()
        }
    }
}


