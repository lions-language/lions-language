use crate::token::{TokenContext, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::control::grammar::{GrammarControl};
use crate::grammar::{GrammarParser, ExpressContext};

pub struct EqualToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for EqualToken {
    fn nup(&self, grammar: &mut GrammarParser<T>, express_context: &ExpressContext<T>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led(&self, grammar: &mut GrammarParser<T>, express_context: &ExpressContext<T>) -> TokenMethodResult {
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

