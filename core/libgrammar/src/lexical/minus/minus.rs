use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult};
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

