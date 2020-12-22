use libresult::{DescResult};
use libtype::instruction::{ConditionStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{WhileStmtContext, BlockDefineContext};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_while_stmt_start(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_while_stmt_expr_start(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_while_stmt_expr_end(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * 获取表达式的计算结果地址
         * */
        let value = match self.scope_context.take_top_from_value_buffer() {
            Ok(v) => v,
            Err(e) => {
                return e;
            }
        };
        /*
         * 判断表达式的结果是否是 boolean 类型
         * */
        if !value.typ_ref().is_boolean() {
            return DescResult::Error(
                format!("expect boolean, but meet: {:?}", value.typ_ref()));
        }
        *stmt_context.expr_result_addr_mut() = value.addr_ref().addr_clone();
        DescResult::Success
    }

    pub fn process_while_stmt_end(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        let cur_index = self.cb.current_index();
        DescResult::Success
    }
}

