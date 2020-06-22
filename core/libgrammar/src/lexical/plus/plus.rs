use crate::grammar::{GrammarParser, ExpressContext, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};

lazy_static!{
    static ref plus_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &20,
        oper_type: &TokenOperType::Operator
    };
}

pub struct PlusToken {
    context: TokenContext
}

impl PlusToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 移除 + token
         * */
        let t = grammar.take_next_one();
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
                grammar.panic("expect one token, but found EOF");
                return TokenMethodResult::Panic;
            }
        };
        // println!("{}", tp.as_ref::<T, CB>().context.token_type.format());
        let r =  grammar.expression(token.token_attrubute().bp, express_context, &tp);
        match r {
            TokenMethodResult::End
                | TokenMethodResult::IoEOF => {
                /*
                 * 这里的判断实际是多余的, 因为 expression 只可能返回这两个值, 否则都抛出异常了
                 * */
            },
            _ => {
                return r;
            }
        }
        grammar.grammar_context().cb.operator_plus(TokenValue::from_token(t));
        TokenMethodResult::End
    }
}

impl PlusToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*plus_token_attrubute,
            nup: PlusToken::nup,
            led: PlusToken::led
        }
    }
}

