use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType};
use crate::lexical::{CallbackReturnStatus};
use crate::control::grammar::{GrammarControl};

lazy_static!{
    static ref minus_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &20,
        oper_type: &TokenOperType::Operator
    };
}

pub struct MinusToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for MinusToken {
    fn nup(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn led(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*minus_token_attrubute
    }
}

impl MinusToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

