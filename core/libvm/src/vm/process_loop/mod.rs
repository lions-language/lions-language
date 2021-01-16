use libcommon::address::{FunctionAddrValue};
use liblink::{define::LinkDefine};
use libtype::instruction::{LoopStmt
    , BlockDefine, ConditionStmtTrue};
use libtype::{Data, DataValue
    , primeval::PrimevalData
    , primeval::boolean::BooleanValue
    , AddressValue};
use crate::vm::{VirtualMachine, ExecuteResult};

impl VirtualMachine {
    pub fn process_loop_stmt(&mut self, value: LoopStmt) -> ExecuteResult {
        let true_handle = value.fields_move();
        loop {
            /*
             * 执行 true block 的语句
             * */
            match self.process_execute_block_ref(true_handle.define_ref()) {
                ExecuteResult::ReturnFunc => {
                    return ExecuteResult::ReturnFunc;
                },
                ExecuteResult::Normal => {
                },
                ExecuteResult::Jump(_) => {
                    panic!("should not happend");
                }
            }
            // ExecuteResult::Jump(true_handle.jump_clone())
        }
        ExecuteResult::Normal
    }
}

