use crate::token::{self, TokenContext, Token};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::Grammar;

pub struct LeftSquareBracketsToken {
}

impl LeftSquareBracketsToken {
}

impl LeftSquareBracketsToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*token::default_token_attrubute,
            nup: token::default_nup,
            led: token::default_led
        }
    }
}

