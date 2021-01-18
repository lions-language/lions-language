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
        let ld = self.link_define.clone();
        let ld = ld.as_ref::<LinkDefine>();
        let define_addr = true_handle.define_ref().addr_ref();
        let mut block = ld.read(define_addr);
        while let Some(ins) = block.get_next() {
            // println!("{:?}", ins);
            let r = self.execute(ins.clone(), &block.current_pos_clone(), &block.block_length_clone());
            match r {
                ExecuteResult::ReturnFunc => {
                    return ExecuteResult::ReturnFunc;
                },
                ExecuteResult::Jump(jump) => {
                    block.update_by_jump(&jump);
                },
                ExecuteResult::Normal => {
                }
            }
        }
        ExecuteResult::Normal
    }
}

