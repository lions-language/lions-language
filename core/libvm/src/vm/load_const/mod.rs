use libtype::instruction::Instruction;
use crate::vm::{VirtualMachine};
use crate::memory::thread_stack as ts;

impl VirtualMachine {
    pub fn load_const_uint8(&mut self, data: u8) {
        self.thread_stack.push(ts::StackData::Uint8(data));
    }

    pub fn load_const_uint16(&mut self, data: u16) {
        self.thread_stack.push(ts::StackData::Uint16(data));
    }
}

