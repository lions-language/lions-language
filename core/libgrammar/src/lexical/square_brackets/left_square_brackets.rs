use crate::token::{self, TokenContext, Token, TokenMethodResult, TokenType};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct LeftSquareBracketsToken {
}

impl LeftSquareBracketsToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        unimplemented!("expression left square brackets: nup");
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl LeftSquareBracketsToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: LeftSquareBracketsToken::nup,
            led: token::default_led
        }
    }
}

