use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};

lazy_static!{
    static ref plus_plus_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &10,
        oper_type: &TokenOperType::Operator
    };
}

pub struct PlusPlusToken {
}

impl PlusPlusToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>)
        -> TokenMethodResult {
        grammar.prefix_plus_plus_process(express_context)
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>)
        -> TokenMethodResult {
        grammar.suffix_plus_plus_process(express_context)
    }
}

impl PlusPlusToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*plus_plus_token_attrubute,
            nup: PlusPlusToken::nup,
            led: PlusPlusToken::led
        }
    }
}


