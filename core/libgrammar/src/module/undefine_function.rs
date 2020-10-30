use crate::lexical::{LexicalParser, CallbackReturnStatus};
use crate::grammar::{Grammar};
use super::{UndefineFunction};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> UndefineFunction<T, CB> {
    /*
    pub fn new() -> Self {
        Self {
        }
    }
    */
}


