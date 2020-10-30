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
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
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
        grammar.grammar_context().cb.operator_prefix_increase(t.token_value());
        r
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 ++ token
         * */
        let t = grammar.take_next_one();
        grammar.grammar_context().cb.operator_suffix_increase(t.token_value());
        /*
         * 后置运算符, 不用继续查找下一个运算符
         * 但是后缀运算符后面只有如下几种token是合法的
         *  1. 结束串
         *  2. io EOF
         *  3. 后缀运算符 (a++++ <=> a++ ++)
         * */
        let tp = match grammar.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 后缀运算符后面遇到 EOF => 结束 (情况 1)
                 * */
                return TokenMethodResult::StmtEnd;
            }
        };
        let next = tp.as_ref::<T, CB>();
        let cb_r = (express_context.end_f)(grammar, next);
        match cb_r {
            TokenMethodResult::StmtEnd
            | TokenMethodResult::End => {
                /*
                 * 情况 2
                 * */
                return cb_r;
            },
            _ => {
            }
        }
        /*
         * 调用 next 的 led 方法, 处理连续后缀运算符的情况 (情况 3)
         * */
        next.led(grammar, express_context)
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


