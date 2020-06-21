use crate::token::{TokenContext, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct EqualToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for EqualToken {
    fn nup(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl EqualToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

