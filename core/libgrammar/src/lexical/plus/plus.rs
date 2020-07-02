use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};

lazy_static!{
    static ref PLUS_TOKEN_ATTRUBUTE: TokenAttrubute = TokenAttrubute{
        bp: &20,
        oper_type: &TokenOperType::Operator
    };
}

pub struct PlusToken {
}

impl PlusToken {
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
        grammar.grammar_context().cb.operator_positive(TokenValue::from_token(t));
        r
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 + token
         * */
        // println!("{}", token.context.token_type.format());
        let t = grammar.take_next_one();
        /*
         * 注意: 在 take_next_one() 之后, 第一个传入参数已经是无效的了
         * 因为 take_next_one 的 token 和 传入的token是同一个对象(本次调用是由 token 发起的)
         * 所以, 如果想利用 传入的token, 需要在之前就进行值拷贝, 或者使用 take_next_one 的结果
         * (这就是之前 unsafe 可能导致的问题, rust 不让编译, 是有道理的, 幸运的是, 我们知道问题在哪里, 可以合理的使用内存)
         * */
        /*
         * 查找, 直到找到比 + 优先级小或者等于的为止
         * */
        let tp = match grammar.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 操作符之后没有token => 语法错误
                 * */
                grammar.panic("expect one token, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        let r =  grammar.expression(t.token_attrubute().bp, express_context, &tp);
        grammar.grammar_context().cb.operator_plus(TokenValue::from_token(t));
        r
    }
}

impl PlusToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*PLUS_TOKEN_ATTRUBUTE,
            nup: PlusToken::nup,
            led: PlusToken::led
        }
    }
}

