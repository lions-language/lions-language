use crate::token::{self, TokenContext, Token
    , TokenMethodResult};
use crate::lexical::CallbackReturnStatus;
use crate::grammar::{Grammar
    , GrammarParser, ExpressContext};

pub struct AnnotateToken {
}

impl AnnotateToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(
        token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>
        , express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 表达式中遇到注释 => 跳过
         * */
        println!("skip annotate");
        grammar.skip_next_one();
        TokenMethodResult::End
    }
}

impl AnnotateToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: AnnotateToken::nup,
            led: token::default_led
        }
    }
}

