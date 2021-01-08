use libresult::{DescResult};
use libtype::instruction::{IfStmt, BlockDefine
    , Instruction, Jump
    , ConditionStmtTrue
    , JumpType};
use libgrammar::grammar::{IfStmtContext, BlockDefineContext};
use crate::compile::{Compile, Compiler};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn process_if_stmt_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_condition_branch_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_else_branch_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_expr_start(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        DescResult::Success
    }

    pub fn process_if_stmt_expr_end(&mut self, stmt_context: &mut IfStmtContext
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
        *stmt_context.cur_expr_result_addr_mut() = value.addr_ref().addr_clone();
        DescResult::Success
    }

    pub fn process_if_stmt_condition_branch_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        /*
         * 生成一条分支指令 (记录: 表达式地址 / 表达式为true情况下执行的块地址
         *  / 表达式为false情况下执行的块地址(这个时候无法知道false情况下的块地址, 所以暂时保留))
         * */
        // println!("{:?}, {:?}", stmt_context, define_context);
        self.cb.condition_stmt(IfStmt::new_with_all(
                stmt_context.cur_expr_result_addr_clone()
                , ConditionStmtTrue::new_with_all(
                    BlockDefine::new_with_all(define_context.define_addr_clone())
                        , Jump::default())));
        /*
         * 将这条指令的索引记录保存在 stmt context 中的 last instruction index 中
         * */
        /*
         * TODO: 这里应该记录指令的地址, 而不是索引
         * */
        *stmt_context.last_condition_instruction_index_mut() =
            Some(self.cb.current_index());
        stmt_context.condition_instructure_indexs_mut().push(self.cb.current_index());
        DescResult::Success
    }

    pub fn process_if_stmt_else_branch_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        self.cb.execute_block(BlockDefine::new_with_all(
                define_context.define_addr_clone()));
        DescResult::Success
    }

    pub fn process_if_stmt_end(&mut self, stmt_context: &mut IfStmtContext
        , define_context: &mut BlockDefineContext) -> DescResult {
        let cur_index = self.cb.current_index();
        let indexs = stmt_context.condition_instructure_indexs_ref();
        for index in indexs {
            let mut ptr = self.cb.get_current_instructure_ptr(*index);
            let ins = ptr.as_mut::<Instruction>();
            match ins {
                Instruction::ConditionStmt(v) => {
                    /*
                     * 将 当前 分支的 指令(else 开始)的地址写入
                     * */
                    *v.true_handle_mut().jump_mut() =
                        Jump::new_with_all(JumpType::Backward
                            , cur_index - index);
                },
                _ => {
                    panic!("expect ConditionStmt, but meet {:?}", ins);
                }
            }
        }
        DescResult::Success
    }
}
