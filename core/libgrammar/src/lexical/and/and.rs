use crate::token::{self, TokenContext, Token
    , TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{Grammar
    , GrammarParser, ExpressContext};

pub struct AndToken {
}

impl AndToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(
        token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.and_process();
        TokenMethodResult::End
    }
}

impl AndToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: AndToken::nup,
            led: token::default_led
        }
    }
}

