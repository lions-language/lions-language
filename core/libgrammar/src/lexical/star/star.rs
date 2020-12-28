use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};
use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct StarToken {
}

lazy_static!{
    static ref star_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &21,
        oper_type: &TokenOperType::Operator
    };
}

impl StarToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        grammar.nup_star_process();
        TokenMethodResult::End
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &mut ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 * token
         * */
        let t = grammar.take_next_one();
        /*
         * 查找, 直到找到比 * 优先级小或者等于的为止
         * */
        let tp = match grammar.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * *号 后面遇到了 EOF => 语法错误
                 * */
                grammar.panic("expect operand, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        let r = grammar.expression(t.token_attrubute().bp, express_context, &tp);
        grammar.grammar_context().cb.operator_multiplication(t.token_value());
        r
    }
}

impl StarToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*star_token_attrubute,
            nup: StarToken::nup,
            led: StarToken::led
        }
    }
}

