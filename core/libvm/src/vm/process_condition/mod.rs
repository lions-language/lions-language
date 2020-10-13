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
            },
            BooleanValue::False => {
                /*
                 * 执行 false block 的语句
                 * */
            }
        }
    }
}

