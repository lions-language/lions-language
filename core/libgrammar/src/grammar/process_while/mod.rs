use libcommon::ptr::{HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::grammar::{BlockDefineContext, WhileStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn while_process(&mut self) {
        /*
         * 跳过 while 关键字
         * */
        self.skip_next_one();
        /*
         * 解析表达式
         * */
        let tp = match self.skip_white_space_token() {
            Some(tp) => tp,
            None => {
                /*
                 * while 后面没有token
                 *  => while 语句后面必须要有表达式
                 * */
                self.panic("expect expr, but arrive IOEof");
                return;
            }
        };
        let mut stmt_context = WhileStmtContext::default();
        let mut define_context = BlockDefineContext::default();
        check_desc_result!(self, self.cb().while_stmt_start(&mut stmt_context, &mut define_context));
        check_desc_result!(self, self.cb().while_stmt_expr_start(&mut stmt_context, &mut define_context));
        self.expression_process(&tp
            , &mut ExpressContext::new(GrammarParser::<T, CB>::expression_end_left_big_parenthese));
        check_desc_result!(self, self.cb().while_stmt_expr_end(&mut stmt_context, &mut define_context));
        /*
         * 解析 block
         * */
        check_desc_result!(self, self.cb().block_define_start(&mut define_context));
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        self.parse_block_content();
        self.skip_next_one();
        check_desc_result!(self, self.cb().block_define_end(&mut define_context));
        check_desc_result!(self, self.cb().while_stmt_end(&mut stmt_context, &mut define_context));
    }
}
