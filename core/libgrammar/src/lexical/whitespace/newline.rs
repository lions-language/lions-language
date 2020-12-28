use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{self, TokenContext, Token, TokenMethodResult};

pub struct NewLineToken {
}

impl NewLineToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 如果调用 nup 方法的时候, 遇到了 newline, 也就是期待一个操作数, 但是遇到了换行,
         * 操作数可能在下一面一行, 如:
         * 1 +
         * 1
         * 这种情况下, 应该也是需要支持的, 所以这里 skip, 然后继续调用 nup
         * */
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

impl NewLineToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: token::default_token_attrubute(),
            nup: NewLineToken::nup,
            led: token::default_led
        }
    }
}

