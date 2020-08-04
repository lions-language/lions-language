use libresult::*;
use super::{Grammar, GrammarParser
    , ExpressContext};
use crate::lexical::{CallbackReturnStatus
    , TokenVecItem};
use crate::token::{TokenMethodResult
    , TokenType};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn funccall_process(&mut self, backtrack_len: usize) {
        /*
         * 获取名称
         * */
        let token = self.take_next_one();
        let mut names = vec![token.token_value()];
        /*
         * 因为在之前的 virtual lookup 的时候已经判断了到达这里一定是函数调用
         * 为了效率, 这里不再依次判断, 应该直接跳过, 直到 `(` 之后的 token
         * */
        self.skip_next_n(backtrack_len+1);
        /*
         * 查看下一个有效 token 是否是 `)`
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                self.panic("expect `)` after `(`");
                return;
            }
        };
        let typ = tp.as_ref::<T, CB>().context_token_type();
        let mut param_len = 0;
        match typ {
            TokenType::RightParenthese => {
                /*
                 * xxx() 形式 => 跳过 )
                 * */
                self.skip_next_one();
            },
            _ => {
                self.expression_process(&tp, &ExpressContext::new(
                        GrammarParser::<T, CB>::expression_end_param_list));
                param_len += 1;
                while let Some(p) = self.skip_white_space_token() {
                    let nt = p.as_ref::<T, CB>();
                    match nt.context_token_type() {
                        TokenType::Comma => {
                            self.skip_next_one();
                        },
                        TokenType::RightParenthese => {
                            self.skip_next_one();
                            break;
                        },
                        _ => {
                            panic!("should not happend, {:?}", nt.context_token_type());
                        }
                    }
                    match self.skip_white_space_token() {
                        Some(tp) => {
                            self.expression_process(&tp, &ExpressContext::new(
                                    GrammarParser::<T, CB>::expression_end_param_list));
                            param_len += 1;
                        },
                        None => {
                            /*
                             * 没有遇到闭合的 `)`, 就到达了文件 结尾 => 语法错误
                             * */
                            self.panic("expect expression, but found arrive IOEOF");
                        }
                    }
                }
                // println!("param len: {}", param_len);
            }
        }
        if let DescResult::Error(s) = self.cb().call_function(param_len, names) {
            self.panic(&s);
        };
    }
}

