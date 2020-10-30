use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone> GrammarParser<'a, T, CB> {
    pub fn annotate_process(&mut self) {
        let next = self.take_next_one();
        self.cb().annotate(next.token_value());
    }
}
