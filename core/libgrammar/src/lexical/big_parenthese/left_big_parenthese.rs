use crate::token::{self, TokenContext, Token
    , TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{Grammar
    , GrammarParser, ExpressContext};

pub struct LeftBigParentheseToken {
}

impl LeftBigParentheseToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(
        token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
        , express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.process_block();
        TokenMethodResult::End
    }
}

impl LeftBigParentheseToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: LeftBigParentheseToken::nup,
            led: token::default_led
        }
    }
}

