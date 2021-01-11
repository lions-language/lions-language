use libcommon::address::{FunctionAddrValue};
use liblink::{define::LinkDefine};
use libtype::instruction::{ConditionStmt
    , BlockDefine, ConditionStmtTrue};
use libtype::{Data, DataValue
    , primeval::PrimevalData
    , primeval::boolean::BooleanValue
    , AddressValue};
use crate::vm::{VirtualMachine, ExecuteResult
    , ConditionResult};

impl VirtualMachine {
    pub fn process_condition_stmt(&mut self, value: ConditionStmt) -> ExecuteResult {
        let expr_value = self.thread_context.current_unchecked().get_data_unchecked(
            value.expr_addr_ref(), &self.link_static);
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
            },
            BooleanValue::False => {
            }
        }
        unimplemented!();
    }
}

