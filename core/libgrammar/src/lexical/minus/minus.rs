use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};
use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

lazy_static!{
    static ref minus_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &20,
        oper_type: &TokenOperType::Operator
    };
}

pub struct MinusToken {
}

impl MinusToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 token
         * */
        let t = grammar.take_next_one();
        /*
         * 找到下一个 token, 然后调用下一个 token 的 nup
         * */
        let tp = match grammar.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * - 后面遇到了 EOF => 语法错误
                 * */
                grammar.panic("expect operand, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        let next = tp.as_ref::<T, CB>();
        let r = next.nup(grammar, express_context);
        match r {
            TokenMethodResult::None => {
                grammar.panic(&format!("expect operand, but found: {:?}", next.context_token_type()));
                return TokenMethodResult::Panic;
            },
            _ => {
            }
        }
        grammar.grammar_context().cb.operator_negative(t.token_value());
        r
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
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
        grammar.grammar_context().cb.operator_minus(t.token_value());
        r
    }
}

impl MinusToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar + Clone>(
        context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*minus_token_attrubute,
            nup: MinusToken::nup,
            led: MinusToken::led
        }
    }
}

