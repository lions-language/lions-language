use super::{GrammarParser, Grammar};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn process_block(&mut self) {
        /*
         * 跳过 `{`
         * */
        self.skip_next_one();
        self.cb().anonymous_block_start();
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
                    }
                });
            }
        }
        /*
         * 到达这里说明 next token 是 } => 跳过 `}`
         * */
        let t = self.skip_next_one();
        self.cb().anonymous_block_end();
    }
}
