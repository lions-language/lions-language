use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult};
use crate::lexical::{CallbackReturnStatus};
use crate::control::grammar::{GrammarControl};
use crate::grammar::{GrammarParser, ExpressContext};

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
    fn nup(&self, grammar: &mut GrammarParser<T>, express_context: &ExpressContext<T>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led(&self, grammar: &mut GrammarParser<T>, express_context: &ExpressContext<T>) -> TokenMethodResult {
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

