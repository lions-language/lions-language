use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn backticks_process(&mut self) {
        self.content.skip_next_one();
    }
}
