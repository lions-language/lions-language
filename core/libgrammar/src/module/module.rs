use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{Grammar};
use super::{Module};
use std::collections::{HashMap};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Module<T, CB> {
    pub fn new() -> Self {
        Self {
            undef_funcs: HashMap::new()
        }
    }
}


