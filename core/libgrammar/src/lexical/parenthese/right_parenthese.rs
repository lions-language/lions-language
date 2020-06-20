use crate::token::{TokenContext, Token};
use crate::lexical::CallbackReturnStatus;
use crate::control::grammar::GrammarControl;

pub struct RightParentheseToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for RightParentheseToken {
    fn nup(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn led(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
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

