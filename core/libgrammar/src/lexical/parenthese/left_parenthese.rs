use crate::token::{self, TokenContext, Token, TokenMethodResult, TokenType};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct LeftParentheseToken {
}

impl LeftParentheseToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.expression_process_start_with_parenthese()
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }
}

impl LeftParentheseToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: LeftParentheseToken::nup,
            led: token::default_led
        }
    }
}

