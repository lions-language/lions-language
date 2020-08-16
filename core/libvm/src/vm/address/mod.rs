use libtype::instruction::{AddressBind};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn address_bind(&mut self, context: AddressBind) {
        self.thread_context.current_mut_unchecked()
            .add_bind(dst_addr.addr_clone()
                , src_addr.typ_clone(), src_data_addr);
    }
}
