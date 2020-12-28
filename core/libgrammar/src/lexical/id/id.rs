use libresult::DescResult;
use libtype::{TypeAttrubute};
use crate::grammar::{GrammarParser
    , ExpressContext, Grammar
    , LoadVariantContext, LoadVariantContextValue
    , DescContext};
use crate::token::TokenMethodResult;
use crate::token::{self, Token, TokenOperType, TokenAttrubute, TokenContext
    , TokenType};
use crate::lexical::CallbackReturnStatus;

pub struct IdToken {
    context: TokenContext
}

lazy_static!{
    static ref ID_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl IdToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(
        token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.id_process(DescContext::new(
                TypeAttrubute::default()));
        TokenMethodResult::End
    }
}

impl IdToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*ID_TOKEN_ATTRUBUTE,
            nup: IdToken::nup,
            led: token::default_led
        }
    }
}


