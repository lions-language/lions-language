use crate::token::{TokenContext, Token, TokenAttrubute, TokenOperType, TokenMethodResult, TokenValue};
use crate::lexical::{CallbackReturnStatus};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct MultiplicationToken {
}

lazy_static!{
    static ref multiplication_token_attrubute: TokenAttrubute = TokenAttrubute{
        bp: &21,
        oper_type: &TokenOperType::Operator
    };
}

impl MultiplicationToken {
    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        TokenMethodResult::None
    }

    fn led<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>, grammar: &mut GrammarParser<T, CB>, express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
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
        grammar.grammar_context().cb.operator_multiplication(TokenValue::from_token(t));
        r
    }
}

impl MultiplicationToken {
    pub fn new<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(context: TokenContext) -> Token<T, CB> {
        Token{
            context: context,
            attrubute: &*multiplication_token_attrubute,
            nup: MultiplicationToken::nup,
            led: MultiplicationToken::led
        }
    }
}

