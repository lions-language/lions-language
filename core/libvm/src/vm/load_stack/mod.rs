use libtype::instruction::*;
use libtype::{AddressType, AddressValue};
use crate::memory::{Rand};
use crate::vm::{VirtualMachine};
use crate::data::Data;

impl VirtualMachine {
    pub fn load_stack(&mut self, value: LoadStack) {
        /*
         * 将给定的地址绑定到栈区
         * */
        let (addr, data) = value.fields_move();
        self.thread_context.current_mut_unchecked()
            .alloc_and_write_data(&addr, data);
    }
}

