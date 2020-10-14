use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , ReturnStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn return_process(&mut self) {
        /*
         * 跳过 return 关键字
         * */
        self.skip_next_one();
        let tp = match self.lookup_next_one_ptr() {
            Some(tp) => tp,
            None => {
                /*
                 * return 后面没有token
                 *  => return 语句不能在函数外部, 所以, return 语句之后不应该没有token
                 *  要么是 `}`, 或者是 `;`, 或者是 其他表达式
                 * */
                self.panic("expect `}` / `;` / expr, but arrive IOEof");
                return;
            }
        };
        let mut is_exist_expr = false;
        let next = tp.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::Semicolon => {
                // return;
                self.skip_next_one();
            },
            TokenType::RightBigParenthese => {
                // return }
            },
            TokenType::NewLine => {
                let wst = match self.skip_white_space_token() {
                    Some(t) => t,
                    None => {
                        self.panic("expect `}` / expr, but arrive IOEof");
                        return;
                    }
                };
                let wstoken = wst.as_ref::<T, CB>();
                match wstoken.context_token_type() {
                    TokenType::RightBigParenthese => {
                        /*
                         *  return
                         * }
                         * */
                    },
                    _ => {
                        is_exist_expr = true;
                        self.expression_process(&tp
                            , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_block));
                    }
                }
            },
            _ => {
                is_exist_expr = true;
                self.expression_process(&tp
                    , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_block));
            }
        }
        let context = ReturnStmtContext{
            is_exist_expr: is_exist_expr
        };
        match self.cb().return_stmt(context) {
            DescResult::Error(e) => {
                self.panic(&e);
            },
            _ => {}
        }
    }
}

