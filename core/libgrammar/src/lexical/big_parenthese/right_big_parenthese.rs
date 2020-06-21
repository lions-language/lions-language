use crate::token::{TokenContext, Token};
use crate::lexical::CallbackReturnStatus;
use crate::control::grammar::GrammarControl;
use crate::grammar::Grammar;

pub struct RightBigParentheseToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for RightBigParentheseToken {
    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl RightBigParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

