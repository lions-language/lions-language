use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};
use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

lazy_static!{
    static ref right_arrow_token_attrubute: TokenAttrubute = TokenAttrubute::default();
}

pub struct RightArrowToken {
}

impl RightArrowToken {
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

impl RightArrowToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*right_arrow_token_attrubute,
            nup: RightArrowToken::nup,
            led: RightArrowToken::led
        }
    }
}

