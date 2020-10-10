use libcommon::ptr::{HeapPtr};
use libcommon::address::{FunctionAddrValue};
use libresult::{DescResult};
use super::{GrammarParser, Grammar, NextToken, ExpressContext
    , VarStmtContext};
use crate::grammar::{BlockDefineContext, IfStmtContext};
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
        let mut stmt_context = IfStmtContext::default();
        let mut define_context = BlockDefineContext::default();
        self.cb().if_stmt_start(&mut stmt_context, &mut define_context);
        self.cb().if_stmt_branch_start(&mut stmt_context, &mut define_context);
        self.cb().if_stmt_expr_start(&mut stmt_context, &mut define_context);
        self.expression_process(&tp
            , &ExpressContext::new(GrammarParser::<T, CB>::expression_end_left_big_parenthese));
        self.cb().if_stmt_expr_end(&mut stmt_context, &mut define_context);
        /*
         * 解析 block
         * */
        self.expect_and_take_next_token_unchecked(TokenType::LeftBigParenthese);
        /*
         * 跳过 `{`
         * */
        // self.skip_next_one();
        self.cb().block_define_start(&mut define_context);
        self.parse_block_content();
        /*
         * 到达这里说明 next token 是 } => 跳过 `}`
         * */
        self.skip_next_one();
        self.cb().block_define_end(&mut define_context);
        self.cb().if_stmt_branch_end(&mut stmt_context, &mut define_context);
        self.cb().if_stmt_end(&mut stmt_context, &mut define_context);
    }
}
