use crate::token::{self, Token, TokenOperType, TokenAttrubute, TokenContext, TokenMethodResult, TokenValue};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct NumberToken {
}

lazy_static!{
    static ref number_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &0,
        oper_type: &TokenOperType::Operand
    };
}

impl NumberToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        let mut token_value = grammar.take_next_one().token_value();
        grammar.grammar_context().cb.const_number(token_value);
        TokenMethodResult::End
    }
}

impl NumberToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*number_token_attrubute,
            nup: NumberToken::nup,
            led: token::default_led
        }
    }
}


