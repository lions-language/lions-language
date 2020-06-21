use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn square_brackets_left_process(&mut self) {
    }

    pub fn square_brackets_right_process(&mut self) {
    }
}

