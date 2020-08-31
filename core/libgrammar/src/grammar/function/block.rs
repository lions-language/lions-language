use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus};
use crate::token::{TokenType};
use crate::grammar::{FunctionDefineContext};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn function_parse_block(&mut self
        , define_context: &mut FunctionDefineContext) {
        /*
         * 查找 {
         * */
        self.expect_next_token(|parser, t| {
            let token = t.as_ref::<T, CB>();
            let tt = token.context_token_type();
            match tt {
                TokenType::LeftBigParenthese => {
                },
                _ => {
                    parser.panic(&format!("expect `{}`, but found {:?}", "{", tt));
                }
            }
        }, "`{`");
        /*
         * 如果没有 panic, 那么一定可以 take 到下一个 token
         * */
        let next = self.take_next_one();
        self.cb().function_define_start(next.token_value());
        /*
        match self.expect_and_take_next_token(TokenType::LeftBigParenthese) {
            NextToken::<T, CB>::False(t) => {
                return;
            },
            NextToken::<T, CB>::True(t) => {
                /*
                 * 回调定义开始
                 * */
                self.cb().function_define_start(TokenValue::from_token(t));
            },
            _ => {
                return;
            }
        }
        */
        /*
         * { 后面可能是语句, 也可能是 } (空语句)
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect `}` or function body, but arrive IO EOF");
                return;
            }
        };
        let next = tp.as_ref::<T, CB>();
        match next.context_ref().token_type() {
            TokenType::RightBigParenthese => {
                /*
                 * { 后面是 }
                 * */
            },
            _ => {
                /*
                 * { 后面是语句块 => 处理语句块
                 * */
                self.parser_inner(|grammar, token_ptr| {
                    let tp = match token_ptr {
                        Some(tp) => {
                            tp
                        },
                        None => {
                            /*
                             * 到达文件结束
                             * 取出空白后不存在下一个token, 到达了 IO EOF, 但是期望的是 } => 语法错误
                             * */
                            grammar.panic("expect `}`, but arrive IO EOF");
                            return true;
                        }
                    };
                    let token = tp.as_ref::<T, CB>();
                    /*
                     * 如果是 } 就结束, 否则继续
                     * */
                    if let TokenType::RightBigParenthese = token.context_ref().token_type() {
                        /*
                         * 结束
                         * */
                        true
                    } else {
                        false
                        // grammar.panic(&format!("expect `{}`, but found: {:?}", "}", token.context_ref().token_type()));
                    }
                });
                /*
                self.select_with_exprcontext(&tp, &ExpressContext::new(GrammarParser::<T, CB>::expression_end_right_big_parenthese));
                /*
                 * 删除所有的空白
                 * */
                let tp = match self.skip_white_space_token() {
                    Some(tp) => {
                        tp
                    },
                    None => {
                        /*
                         * 取出空白后不存在下一个token, 到达了 IO EOF, 但是期望的是 } => 语法错误
                         * */
                        self.panic("expect `}`, but arrive IO EOF");
                        return;
                    }
                };
                let token = tp.as_ref::<T, CB>();
                /*
                 * 判断是否是 }, 如果不是 } => 语法错误
                 * */
                if let TokenType::RightBigParenthese = token.context_ref().token_type() {
                } else {
                    self.panic(&format!("expect `{}`, but found: {:?}", "}", token.context_ref().token_type()));
                    return;
                }
                */
            }
        }
        /*
         * 到达这里说明 next token 是 } => 表达式结束
         * */
        let t = self.take_next_one();
        self.grammar_context().cb.function_define_end(t.token_value(), define_context);
    }
}

