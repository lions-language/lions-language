use libtype::{AddressValue, AddressKey, AddressType};
use libtype::instruction::{ReturnStmt};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn process_return_stmt(&mut self, value: ReturnStmt) {
        let (scope, addr_key) = value.fields_move();
        /*
         * 1. 找到数据地址
         * 2. 将数据地址写入到指定的作用域中
         * 3. 移除绑定(为了在作用域结束时, 不释放数据内存)
         * */
        /*
         * 1
         * */
        let data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&addr_key).addr_value_clone();
        /*
         * 2
        * */
        self.thread_context.current_mut_unchecked()
            .set_result_data_addr(scope, data_addr);
        /*
         * 3
         * */
        self.thread_context.current_mut_unchecked()
            .remove_bind(addr_key);
    }
}