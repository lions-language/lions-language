use super::{LexicalParser, CallbackReturnStatus};
use crate::grammar::Grammar;

use crate::token::{TokenType};

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> LexicalParser<T, CB> {
    pub fn build_impl_opd(&mut self) {
        let context = self.build_token_context_without_data(TokenType::Impl);
        self.push_to_token_buffer(impl_opd::ImplOpdToken::new(context));
    }

}

mod impl_opd;

