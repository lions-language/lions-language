use libtype::instruction::{ConditionStmt};
use crate::vm::{VirtualMachine};

impl VirtualMachine {
    pub fn process_condition_stmt(&mut self, value: ConditionStmt) {
        /*
         * 计算表达式的结果
         * */
        println!("{:?}", value);
    }
}

