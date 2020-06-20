use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType};
use crate::lexical::{CallbackReturnStatus};
use crate::control::grammar::{GrammarControl};

pub struct DivisionToken {
    context: TokenContext
}

lazy_static!{
    static ref division_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operator
    };
}

impl<T: FnMut() -> CallbackReturnStatus> Token<T> for DivisionToken {
    fn nup(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn led(&self, context: &TokenContext, grammar_control: &mut GrammarControl<T>) {
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*division_token_attrubute
    }
}

impl DivisionToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

