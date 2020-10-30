use crate::token::{self, TokenContext, Token};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::Grammar;

pub struct RightSquareBracketsToken {
}

impl RightSquareBracketsToken {
}

impl RightSquareBracketsToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: token::default_nup,
            led: token::default_led
        }
    }
}

