use libtype::instruction::{AddressBind};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn address_bind(&mut self, context: AddressBind) {
        let (addr_key, addr_value) = context.fields_move();
        let (addr_typ, compile_addr) = addr_value.fields_move();
        /*
         * 通过 compile_addr 找到数据地址, 然后进行绑定
         * */
        let src_data_addr = self.thread_context.current_mut_unchecked()
            .get_data_addr_unchecked(&compile_addr).get_clone();
        // println!("{:?}, {:?}", addr_key, addr);
        self.thread_context.current_mut_unchecked()
            .add_bind(addr_key
                , addr_typ, src_data_addr);
    }
}
