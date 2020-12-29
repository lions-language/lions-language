use crate::token::{self, TokenContext, TokenAttrubute, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct CommaToken {
}

lazy_static!{
    static ref comma_token_attrubute: TokenAttrubute = token::TokenAttrubute::default();
}

impl CommaToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl CommaToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*comma_token_attrubute,
            nup: CommaToken::nup,
            led: CommaToken::led
        }
    }
}

