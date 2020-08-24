use libtype::{AddressValue, AddressKey, AddressType};
use libtype::instruction::{ReturnStmt};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn process_return_stmt(&mut self, value: ReturnStmt) {
        let (scope, addr_key) = value.fields_move();
        /*
         * 1. 找到数据地址
         * 2. 将数据地址写入到指定的作用域中
         * */
        /*
         * 1
         * */
        let data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&addr_key).addr_value_clone();
        // println!("{:?}", data_addr);
        /*
         * 2
        * */
        self.thread_context.current_mut_unchecked()
            .set_result_data_addr(scope, data_addr);
    }
}
