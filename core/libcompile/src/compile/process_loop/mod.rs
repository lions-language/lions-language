use libresult::{DescResult};
use libtype::instruction::{LoopStmt, BlockDefine
    , ConditionStmt, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{LoopStmtContext, BlockDefineContext};
use crate::compile::{Compile, Compiler, AddressValueExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_loop_stmt_start(&mut self, stmt_context: &mut LoopStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_loop_stmt_end(&mut self, stmt_context: &mut LoopStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        // let cur_index = self.cb.current_index();
        let jump = Jump::new_with_all(JumpType::Backward, 0);
        self.cb.loop_stmt(LoopStmt::new_with_all(
                    ConditionStmtTrue::new_with_all(
                        BlockDefine::new_with_all(define_context.define_addr_clone())
                        , jump)));
        DescResult::Success
    }
}

