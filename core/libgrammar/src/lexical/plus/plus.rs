use crate::control::grammar::{GrammarControl};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult};

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

