use crate::control::grammar::{GrammarControl};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType};

lazy_static!{
    static ref plus_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &20,
        oper_type: &TokenOperType::Operator
    };
}

pub struct PlusToken {
    context: TokenContext
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for PlusToken {
    fn nup(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn led(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*plus_token_attrubute
    }
}

impl PlusToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

