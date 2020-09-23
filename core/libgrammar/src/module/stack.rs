use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{Grammar};
use super::{ModuleStack};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> ModuleStack<T, CB> {
    pub fn new() -> Self {
        Self {
            modules: Vec::new()
        }
    }
}


