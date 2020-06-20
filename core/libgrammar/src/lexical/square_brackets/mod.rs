use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn square_brackets_left_process(&mut self) {
    }

    pub fn square_brackets_right_process(&mut self) {
    }
}

