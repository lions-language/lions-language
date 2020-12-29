use crate::token::{TokenContext, TokenOperType, TokenAttrubute, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct ColonColonToken {
}

lazy_static!{
    static ref colon_colon_token_attrubute: TokenAttrubute = TokenAttrubute::default();
}

impl ColonColonToken {
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

impl ColonColonToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*colon_colon_token_attrubute,
            nup: ColonColonToken::nup,
            led: ColonColonToken::led
        }
    }
}

