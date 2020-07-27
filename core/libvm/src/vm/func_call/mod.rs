use libtype::instruction::{CallFunction};
use libcommon::optcode::{OptCode};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn call_function(&mut self, value: CallFunction) {
        /*
         * 找到定义, 依次读取定义位置的指令序列
         * 然后调用 self.write
         * */
        unimplemented!("call_function: {:?}", value);
    }
}

