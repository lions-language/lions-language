use libresult::{DescResult};
use libgrammar::grammar::{IfStmtContext, BlockDefineContext};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_if_stmt_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_branch_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_expr_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * 获取表达式的计算结果地址
         * */
        DescResult::Success
    }

    pub fn process_if_stmt_expr_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_branch_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }
}
