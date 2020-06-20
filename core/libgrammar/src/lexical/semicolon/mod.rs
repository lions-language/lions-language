use crate::lexical::{LexicalParser, CallbackReturnStatus};
use crate::token::TokenType;

impl<T: FnMut() -> CallbackReturnStatus> LexicalParser<T> {
    pub fn semicolon_process(&mut self) {
        self.push_nooperate_token_to_token_buffer(TokenType::Semicolon);
    }
}
