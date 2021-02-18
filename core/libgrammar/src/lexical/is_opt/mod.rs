use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn build_is_opt(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Is);
        self.push_to_token_buffer(is_opt::IsOptToken::new(context));
    }

}

mod is_opt;

