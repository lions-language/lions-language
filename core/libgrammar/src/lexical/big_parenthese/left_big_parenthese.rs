use crate::token::{TokenContext, Token};
use crate::lexical::CallbackReturnStatus;
use crate::control::grammar::GrammarControl;
use crate::grammar::Grammar;

pub struct LeftBigParentheseToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for LeftBigParentheseToken {
    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl LeftBigParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

