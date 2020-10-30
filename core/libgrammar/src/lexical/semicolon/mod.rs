use crate::lexical::{LexicalParser, CallbackReturnStatus};
use crate::token::TokenType;
use crate::grammar::Grammar;

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn semicolon_process(&mut self) {
        self.content.skip_next_one();
        self.push_nooperate_nodata_token_to_token_buffer(TokenType::Semicolon);
    }
}
