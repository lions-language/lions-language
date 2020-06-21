use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult};
use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct MultiplicationToken {
    context: TokenContext
}

lazy_static!{
    static ref multiplication_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operator
    };
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for MultiplicationToken {
    fn nup(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn context(&self) -> &TokenContext {
        &self.context
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*multiplication_token_attrubute
    }
}

impl MultiplicationToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}

