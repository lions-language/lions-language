use crate::token::{TokenContext, TokenAttrubute, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct TwoPointToken {
}

pub struct TwoPointEqualToken {
}

lazy_static!{
    static ref TWO_POINT_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute::default();
    static ref TWO_POINT_EQUAL_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute::default();
}

impl TwoPointToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(_token: &Token<T, CB>
        , _grammar: &mut GrammarParser<T, CB>
        , _express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(_token: &Token<T, CB>
        , _grammar: &mut GrammarParser<T, CB>
        , _express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl TwoPointToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*TWO_POINT_TOKEN_ATTRUBUTE,
            nup: TwoPointToken::nup,
            led: TwoPointToken::led
        }
    }
}

impl TwoPointEqualToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(_token: &Token<T, CB>
        , _grammar: &mut GrammarParser<T, CB>
        , _express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(_token: &Token<T, CB>
        , _grammar: &mut GrammarParser<T, CB>
        , _express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl TwoPointEqualToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*TWO_POINT_TOKEN_ATTRUBUTE,
            nup: TwoPointEqualToken::nup,
            led: TwoPointEqualToken::led
        }
    }
}

