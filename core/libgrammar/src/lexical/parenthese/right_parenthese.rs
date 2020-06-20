use crate::token::{TokenContext, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::control::grammar::GrammarControl;

pub struct RightParentheseToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for RightParentheseToken {
    fn nup(&self, grammar_control: &mut GrammarControl<T>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led(&self, grammar_control: &mut GrammarControl<T>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }
}

impl RightParentheseToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

