use libtype::{TypeAttrubute};
use crate::token::{self, Token, TokenOperType, TokenAttrubute
    , TokenContext, TokenMethodResult, TokenValue};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar
    , DescContext};

pub struct StringToken {
    context: TokenContext
}

lazy_static!{
    static ref id_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl StringToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(
        token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
        , express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.string_process(DescContext::new(
                TypeAttrubute::Move));
        TokenMethodResult::End
    }
}

impl StringToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*id_token_attrubute,
            nup: StringToken::nup,
            led: token::default_led
        }
    }
}


