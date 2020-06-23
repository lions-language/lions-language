use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{self, TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};

pub struct TabToken {
}

impl TabToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.take_next_one();
        let tp = match grammar.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 期待一个操作数, 但是遇到了 EOF
                 * */
                grammar.panic("expect operand, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        let t = tp.as_ref::<T, CB>();
        return t.nup(grammar, express_context);
    }
}

impl TabToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*token::default_token_attrubute,
            nup: TabToken::nup,
            led: token::default_led
        }
    }
}

