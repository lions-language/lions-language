use super::{LexicalParser, CallbackReturnStatus};
use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn backslash_t(&mut self) {
        self.content.skip_next_one();
    }
}
