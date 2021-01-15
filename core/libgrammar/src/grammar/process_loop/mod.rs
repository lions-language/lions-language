use libcommon::ptr::{HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::grammar::{BlockDefineContext, LoopStmtContext};
use crate::lexical::{CallbackReturnStatus, TokenVecItem, TokenPointer};
use crate::token::{TokenType, TokenValue};

impl<'a, T: FnMut() -> CallbackReturnStatus, CB: Grammar> GrammarParser<'a, T, CB> {
    pub fn loop_process(&mut self) {
        /*
         * 跳过 loop 关键字
         * */
        self.skip_next_one();
        /*
         * 解析 block
         * */
        let mut stmt_context = LoopStmtContext::default();
        let mut define_context = BlockDefineContext::default();
        check_desc_result!(self, self.cb().block_define_start(&mut define_context));
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        self.parse_block_content();
        self.skip_next_one();
        check_desc_result!(self, self.cb().block_define_end(&mut define_context));
        check_desc_result!(self, self.cb().loop_stmt_end(&mut stmt_context, &mut define_context));
    }
}
