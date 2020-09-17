use libtype::instruction::{AddressBind};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn address_bind(&mut self, context: AddressBind) {
        let (src_addr, dst_addr) = context.fields_move();
        /*
         * 通过 compile_addr 找到数据地址, 然后进行绑定
         * */
        let src_data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&dst_addr).addr_value_clone();
        // println!("{:?}, {:?}", addr_key, addr);
        self.thread_context.current_mut_unchecked()
            .add_bind(src_addr
                , src_data_addr);
    }
}
