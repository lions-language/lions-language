use libcommon::address::{FunctionAddrValue};
use liblink::{define::LinkDefine};
use libtype::instruction::{ConditionStmt};
use libtype::{Data, DataValue
    , primeval::PrimevalData
    , primeval::boolean::BooleanValue};
use crate::vm::{VirtualMachine};

impl VirtualMachine {
    pub fn process_condition_stmt(&mut self, value: ConditionStmt) {
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
                    self.execute_block(true_block.addr_ref());
                }
            },
            BooleanValue::False => {
                /*
                 * 执行 false block 的语句
                 * */
                if false_block.addr_ref().is_valid() {
                    self.execute_block(false_block.addr_ref());
                }
            }
        }
    }

    fn execute_block(&mut self, define_addr: &FunctionAddrValue) {
        let ld = self.link_define.clone();
        let ld = ld.as_ref::<LinkDefine>();
        let mut block = ld.read(define_addr);
        while let Some(ins) = block.get_next() {
            // println!("{:?}", ins);
            self.execute(ins.clone(), &block.current_pos_clone(), &block.block_length_clone());
        }
    }
}

