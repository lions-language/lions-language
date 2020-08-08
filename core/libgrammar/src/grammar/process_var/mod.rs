use super::{GrammarParser, Grammar, NextToken, ExpressContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn var_process(&mut self) {
        /*
         * 跳过 var 关键字
         * */
        self.skip_next_one();
        /*
         * var 后面一定是 id
         * */
        self.expect_next_token(|_, _| {
        }, "id after var");
        /*
         * 如果可以正常走到这里, 说明上一步判断结果成功
         * 那么获取 var 后面的 id token
         * */
        let id_token = self.take_next_one();
        self.cb().var_stmt_start(id_token.token_value());
        /*
         * 跳过空白, 并查看下一个 token
         * */
        let next = match self.skip_white_space_token() {
            Some(tp) => {
                tp
            },
            None => {
                /*
                 * var a [EOF]
                 * */
                self.cb().var_stmt_end();
                return;
            }
        };
        /*
         * 后面如果是 : 就处理类型
         * */
        let next = next.as_ref::<T, CB>();
        match next.context_token_type() {
            TokenType::Colon => {
                self.var_process_after_colon();
            },
            TokenType::Equal => {
                self.var_process_after_equal();
            },
            _ => {
                /*
                 * var a
                 * xxx
                 * */
                self.cb().var_stmt_end();
            }
        }
        self.cb().var_stmt_end();
    }

    pub fn var_process_after_colon(&mut self) {
        unimplemented!();
    }

    pub fn var_process_after_equal(&mut self) {
        /*
         * 跳过 `=`
         * */
        self.skip_next_one();
        self.cb().var_stmt_equal();
        /*
         * 处理表达式
         * */
        self.expect_next_token(|parser, tp| {
            parser.expression_process(&tp
                , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_normal));
        }, "expression");
    }
}

