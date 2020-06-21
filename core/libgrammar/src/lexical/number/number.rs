use crate::token::{Token, TokenOperType, TokenAttrubute, TokenContext, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct NumberToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl<T: FnMut() -> CallbackReturnStatus, CB: Grammar> Token<T, CB> for NumberToken {
    fn context_ref(&self) -> &TokenContext {
        return &self.context;
    }

    fn context(self) -> TokenContext {
        self.context
    }

    fn nup(&self, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn token_attrubute(&self) -> &'static TokenAttrubute {
        &*id_token_attrubute
    }
}

impl NumberToken {
    pub fn new(context: TokenContext) -> Self {
        Self{
            context: context
        }
    }
}


