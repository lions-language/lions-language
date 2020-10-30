use crate::token::{TokenContext, TokenAttrubute, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct PointToken {
}

lazy_static!{
    static ref POINT_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute::default();
}

impl PointToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(_token: &Token<T, CB>, _grammar: &mut GrammarParser<T, CB>, _express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(_token: &Token<T, CB>, _grammar: &mut GrammarParser<T, CB>, _express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl PointToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*POINT_TOKEN_ATTRUBUTE,
            nup: PointToken::nup,
            led: PointToken::led
        }
    }
}

