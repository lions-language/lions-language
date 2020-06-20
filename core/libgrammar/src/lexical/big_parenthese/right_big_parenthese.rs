use crate::token::{TokenContext, Token};
use crate::lexical::CallbackReturnStatus;
use crate::control::grammar::GrammarControl;

pub struct RightBigParentheseToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for RightBigParentheseToken {
    fn nup(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn led(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

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

