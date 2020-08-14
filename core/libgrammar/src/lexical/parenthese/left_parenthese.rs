use crate::token::{self, TokenContext, Token, TokenMethodResult, TokenType};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::grammar::{GrammarParser, ExpressContext, Grammar};

pub struct LeftParentheseToken {
}

impl LeftParentheseToken {
    fn expression_end_right_parenthese<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(grammar: &mut GrammarParser<T, CB>, token: &TokenVecItem<T, CB>) -> TokenMethodResult {
        let tp = match grammar.skip_white_space_token_with_input(TokenPointer::from_ref(token)) {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 查找 ) 时, 遇到了 IoEOF => 语法错误
                 * */
                 grammar.panic("expect a `)`, but arrive IoEOF");
                 return TokenMethodResult::Panic;
            }
        };
        let t = tp.as_ref::<T, CB>();
        match t.context_ref().token_type() {
            TokenType::RightParenthese => {
                grammar.skip_next_one();
                return TokenMethodResult::ParentheseEnd;
            },
            _ => {
            }
        }
        TokenMethodResult::Continue
    }

    fn nup<T: FnMut() -> CallbackReturnStatus, CB: Grammar>(token: &Token<T, CB>
        , grammar: &mut GrammarParser<T, CB>
        , express_context: &ExpressContext<T, CB>) -> TokenMethodResult {
        /*
         * 表达式中遇到 ( 符号
         * 1. 先跳过  (
         * 2. 调用 expression (因为 小括号内的可以视为一个完整的语句)
         * */
        grammar.skip_next_one();
        let tp = match grammar.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * ( 后面是 EOF => 语法错误
                 * */
                grammar.panic("expect operand after `(`, but arrive EOF");
                return TokenMethodResult::Panic;
            }
        };
        grammar.expression(&0, &ExpressContext::new(LeftParentheseToken::expression_end_right_parenthese), &tp)
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

