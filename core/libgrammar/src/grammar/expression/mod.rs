use super::{GrammarParser, ExpressContext};
use crate::lexical::{CallbackReturnStatus, TokenPointer, TokenVecItem};
use crate::token::{TokenType, TokenMethodResult};

impl<T: FnMut() -> CallbackReturnStatus> GrammarParser<T> {
    fn expression_end_normal(token: &TokenVecItem<T>) -> bool {
        match token.context().token_type {
            TokenType::Semicolon
            | TokenType::NewLine => {
                true
            },
            _ => {
                false
            }
        }
    }

    pub fn expression_process(&mut self, token: &TokenPointer) {
        self.update_current_token(token.clone());
        /*
         * 因为 0 比任何的操作数都要小, 所以可以将整个表达式遍历完全
         * */
        self.expression(0, &ExpressContext::new(GrammarParser::<T>::expression_end_normal));
    }

    /*
     * 找到比输入的优先级小的操作符为止
     * 1. 方法返回时, 下一个 token 应该是操作符
     * 2. token 的 nup方法结束后, 下一个 token 应该是 操作符 (或者是结束符)
     * 3. token 的 led方法结束后, 下一个 token 应该是 操作符
     * 4. 提供一个函数指针, 用于判断是否结束 (不需要捕获周边环境, 所以使用函数指针, 提高性能)
     * */
    fn expression(&mut self, operator_bp: u8, express_context: &ExpressContext<T>) {
        let current_token = self.current_token.as_ref::<T>();
        match current_token.nup(self, express_context) {
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
        if (express_context.end_f)(next_token) {
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
            match next_token.led(self, express_context) {
                TokenMethodResult::Expression(bp) => {
                    /*
                     * 计算表达式
                     * */
                    self.expression(bp, express_context);
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

