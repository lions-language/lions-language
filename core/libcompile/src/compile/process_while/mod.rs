use libresult::{DescResult};
use libtype::instruction::{WhileStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{WhileStmtContext, BlockDefineContext};
use crate::compile::{Compile, Compiler, AddressValueExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_while_stmt_start(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_while_stmt_expr_start(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        let cur_index = self.cb.current_index();
        let expr_stmt_addr = stmt_context.expr_stmt_addr_mut();
        *expr_stmt_addr.index_mut() = cur_index + 1;
        DescResult::Success
    }

    pub fn process_while_stmt_expr_end(&mut self, stmt_context: &mut WhileStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * 获取表达式的计算结果地址
         * */
        let cur_index = self.cb.current_index();
        let expr_stmt_addr = stmt_context.expr_stmt_addr_mut();
        *expr_stmt_addr.valid_mut() = true;
        *expr_stmt_addr.length_mut() = cur_index - *expr_stmt_addr.index_ref() + 2;
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
        /*
         * +1 的原因: 需要跳过 后面的 while_stmt 指令
         * */
        let jump = Jump::new_with_all(JumpType::Backward, 0);
        self.cb.while_stmt(WhileStmt::new_with_all(
                    BlockDefine::new_with_all(stmt_context.expr_stmt_addr_clone())
                    , stmt_context.expr_result_addr_clone()
                    , ConditionStmtTrue::new_with_all(
                        BlockDefine::new_with_all(define_context.define_addr_clone())
                        , jump)));
        DescResult::Success
    }
}

