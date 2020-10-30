use crate::token::{TokenContext, TokenAttrubute, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct ThreePointToken {
}

lazy_static!{
    static ref THREE_POINT_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute::default();
}

impl ThreePointToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(_token: &Token<T, CB>, _grammar: &mut GrammarParser<T, CB>, _express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(_token: &Token<T, CB>, _grammar: &mut GrammarParser<T, CB>, _express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl ThreePointToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*THREE_POINT_TOKEN_ATTRUBUTE,
            nup: ThreePointToken::nup,
            led: ThreePointToken::led
        }
    }
}

