use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};

lazy_static!{
    static ref left_angular_bracket_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &12,
        oper_type: &TokenOperType::Operator
    };
}

pub struct LeftAngularBracketToken {
}

impl LeftAngularBracketToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>, express_context: &mut ExpressContext<T, CB>)
        -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>, express_context: &mut ExpressContext<T, CB>)
        -> TokenMethodResult {
        grammar.left_angular_bracket_process(express_context)
    }
}

impl LeftAngularBracketToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*left_angular_bracket_token_attrubute,
            nup: LeftAngularBracketToken::nup,
            led: LeftAngularBracketToken::led
        }
    }
}


