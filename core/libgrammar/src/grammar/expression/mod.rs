use super::{GrammarParser};
use crate::lexical::{CallbackReturnStatus, TokenPointer, TokenVecItem};
use crate::token::{TokenType, TokenMethodResult};

impl<T: FnMut() -> CallbackReturnStatus> GrammarParser<T> {
    pub fn expression_process(&mut self, token: &TokenPointer) {
        self.update_current_token(token.clone());
        /*
         * 因为 0 比任何的操作数都要小, 所以可以将整个表达式遍历完全
         * */
        self.expression(0, &mut |token| -> bool {
            match token.context().token_type {
                TokenType::Semicolon
                | TokenType::NewLine => {
                    true
                },
                _ => {
                    false
                }
            }
        });
    }

    /*
     * 找到比输入的优先级小的操作符为止
     * 1. 方法返回时, 下一个 token 应该是操作符
     * 2. token 的 nup方法结束后, 下一个 token 应该是 操作符 (或者是结束符)
     * 3. token 的 led方法结束后, 下一个 token 应该是 操作符
     * */
    fn expression<EndF: FnMut(&TokenVecItem<T>) -> bool>(&mut self, operator_bp: u8, end_f: &mut EndF) {
        let current_token = self.current_token.as_ref::<T>();
        match current_token.nup(&mut self.control) {
            TokenMethodResult::None => {
                self.panic(&format!("expect operand, but found {}", current_token.context().token_type.format()));
            },
            _ => {}
        }
        /*
         * 检测是否需要结束
         * 一条语句的结束一定在操作数之后
         * */
        let next_tp = match self.control.lookup_next_one_ptr() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * 操作数之后是 EOF => 结束
                 * */
                return;
            }
        };
        let mut next_token = next_tp.as_ref::<T>();
        if end_f(next_token) {
            /*
             * 语句结束
             * */
            return;
        }
        /*
         * 如果到达这里, 说明 next_token 是操作符
         * 比较优先级, 找到比输入的小(或者等于)的为止 (也就是说 只要大于就继续)
         * */
        while next_token.token_attrubute().bp > &operator_bp {
            match next_token.led(&mut self.control) {
                TokenMethodResult::Expression(bp) => {
                    /*
                     * 计算表达式
                     * */
                    self.expression(bp, end_f);
                },
                TokenMethodResult::None => {
                    /*
                     * 操作符的 led 方法没有实现
                     * */
                    panic!(format!("operator: {} not implement", next_token.context().token_type.format()));
                }
            }
            let tp = match self.control.lookup_next_one_ptr() {
                Some(tp) => {
                    tp
                },
                None => {
                    self.panic("");
                    return;
                }
            };
        }
    }
}

