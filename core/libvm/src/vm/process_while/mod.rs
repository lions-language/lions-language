use libcommon::address::{FunctionAddrValue};
use liblink::{define::LinkDefine};
use libtype::instruction::{WhileStmt
    , BlockDefine, ConditionStmtTrue};
use libtype::{Data, DataValue
    , primeval::PrimevalData
    , primeval::boolean::BooleanValue
    , AddressValue};
use crate::vm::{VirtualMachine, ExecuteResult};

enum ConditionResult {
    True,
    False
}

impl VirtualMachine {
    pub fn process_while_stmt(&mut self, value: WhileStmt) -> ExecuteResult {
        let (expr_stmt_addr, expr_addr, true_handle) = value.fields_move();
        let mut execute_result = ExecuteResult::Normal;
        loop {
            let (cond_res, exe_res) = self.condition_handle(&expr_stmt_addr, &expr_addr, &true_handle);
            execute_result = exe_res;
            match cond_res {
                ConditionResult::True => {
                },
                ConditionResult::False  => {
                    break;
                }
            }
        }
        execute_result
    }

    fn condition_handle(&mut self, expr_stmt_addr: &BlockDefine, expr_addr: &AddressValue
        , true_handle: &ConditionStmtTrue) -> (ConditionResult, ExecuteResult) {
        /*
         * 计算表达式的结果
         * */
        let expr_value = self.thread_context.current_unchecked().get_data_unchecked(
            expr_addr, &self.link_static);
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
                match self.process_execute_block_ref(expr_stmt_addr) {
                    ExecuteResult::ReturnFunc => {
                        return (ConditionResult::True, ExecuteResult::ReturnFunc);
                    },
                    ExecuteResult::Normal => {
                    },
                    ExecuteResult::Jump(_) => {
                        panic!("should not happend");
                    }
                }
                /*
                 * 执行 true block 的语句
                 * */
                match self.process_execute_block_ref(true_handle.define_ref()) {
                    ExecuteResult::ReturnFunc => {
                        return (ConditionResult::True, ExecuteResult::ReturnFunc);
                    },
                    ExecuteResult::Normal => {
                    },
                    ExecuteResult::Jump(_) => {
                        panic!("should not happend");
                    }
                }
                (ConditionResult::True, ExecuteResult::Jump(true_handle.jump_clone()))
            },
            BooleanValue::False => {
                (ConditionResult::False, ExecuteResult::Normal)
            }
        }
        /*
        let r = self.process_execute_block_ref(true_handle.define_ref());
        println!("{:?}", r);
        match r {
            ExecuteResult::ReturnFunc => {
                return (ConditionResult::True, ExecuteResult::ReturnFunc);
            },
            ExecuteResult::Normal => {
            },
            ExecuteResult::Jump(_)
                | ExecuteResult::Condition(_) => {
                panic!("should not happend");
            }
        }
        (ConditionResult::True, ExecuteResult::Jump(true_handle.jump_clone()))
        */
    }
}

