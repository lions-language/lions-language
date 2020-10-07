use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn if_process(&mut self) {
        /*
         * 跳过 if 关键字
         * */
        self.skip_next_one();
        /*
         * 解析表达式
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                /*
                 * if 后面没有token
                 *  => if 语句后面必须要有表达式
                 * */
                self.panic("expect expr, but arrive IOEof");
                return;
            }
        };
        self.expression_process(&tp
            , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_left_big_parenthese));
        /*
         * 解析 block
         * */
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        self.process_block();
    }
}