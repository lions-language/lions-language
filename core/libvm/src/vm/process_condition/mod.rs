use libcommon::address::{FunctionAddrValue};
use liblink::{define::LinkDefine};
use libtype::instruction::{ConditionStmt};
use libtype::{Data, DataValue
    , primeval::PrimevalData
    , primeval::boolean::BooleanValue};
use crate::vm::{VirtualMachine, ExecuteResult};

impl VirtualMachine {
    pub fn process_condition_stmt(&mut self, value: ConditionStmt) -> ExecuteResult {
        let (expr_addr, true_block, false_block) = value.fields_move();
        /*
         * 计算表达式的结果
         * */
        let expr_value = self.thread_context.current_unchecked().get_data_unchecked(
            &expr_addr, &self.link_static);
        let data = expr_value.as_ref::<Data>();
        let boolean_value = match data.value_ref() {
            DataValue::Primeval(v) => {
                match v {
                    PrimevalData::Boolean(bv) => {
                        bv
                    },
                    _ => {
                        panic!("expect boolean, but meet {:?}", v);
                    }
                }
            },
            _ => {
                panic!("expect boolean, but meet {:?}", data.value_ref());
            }
        };
        match boolean_value.value_ref() {
            BooleanValue::True => {
                /*
                 * 执行 true block 的语句
                 * */
                if true_block.addr_ref().is_valid() {
                    match self.execute_block(true_block.addr_ref()) {
                        ExecuteResult::ReturnFunc => {
                            return ExecuteResult::ReturnFunc;
                        },
                        ExecuteResult::Normal => {
                        }
                    }
                }
            },
            BooleanValue::False => {
                /*
                 * 跳转到下一个指定的语句中
                 * */
                if false_block.addr_ref().is_valid() {
                    match self.execute_block(false_block.addr_ref()) {
                        ExecuteResult::ReturnFunc => {
                            return ExecuteResult::ReturnFunc;
                        },
                        ExecuteResult::Normal => {
                        }
                    }
                }
            }
        }
        ExecuteResult::Normal
    }

    fn execute_block(&mut self, define_addr: &FunctionAddrValue) -> ExecuteResult {
        let ld = self.link_define.clone();
        let ld = ld.as_ref::<LinkDefine>();
        let mut block = ld.read(define_addr);
        while let Some(ins) = block.get_next() {
            // println!("{:?}", ins);
            match self.execute(ins.clone(), &block.current_pos_clone(), &block.block_length_clone()) {
                ExecuteResult::ReturnFunc => {
                    return ExecuteResult::ReturnFunc;
                },
                ExecuteResult::Normal => {
                }
            }
        }
        ExecuteResult::Normal
    }
}

