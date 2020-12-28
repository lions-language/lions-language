use crate::token::{TokenContext, TokenOperType, TokenAttrubute, Token, TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct EqualEqualToken {
}

lazy_static!{
    static ref equal_equal_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &10,
        oper_type: &TokenOperType::Operator
    };
}

impl EqualEqualToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.equal_equal_process(express_context)
    }
}

impl EqualEqualToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*equal_equal_token_attrubute,
            nup: EqualEqualToken::nup,
            led: EqualEqualToken::led
        }
    }
}


