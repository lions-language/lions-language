use libtype::{AddressValue, AddressKey, AddressType};
use libtype::instruction::{DeleteData};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn delete_data(&mut self, value: DeleteData) {
        let addr = value.fields_move();
        /*
         * 1. 找到数据地址, 删除掉
         * 2. 删除映射
         * */
        let src_data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&addr).clone();
        self.thread_context.current_mut_unchecked()
            .free_data(src_data_addr);
        /*
        self.thread_context.current_mut_unchecked()
            .remove_bind(addr.addr());
        */
    }
}

