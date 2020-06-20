use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult};
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
    fn nup(&self, grammar_control: &mut GrammarControl<T>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led(&self, grammar_control: &mut GrammarControl<T>) -> TokenMethodResult {
        TokenMethodResult::None
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

