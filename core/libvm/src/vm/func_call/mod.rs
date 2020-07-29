use libtype::instruction::{CallFunction};
use libcommon::optcode::{OptCode};
use libcommon::address::{FunctionAddrValue, FunctionAddress};
use libcompile::define_stream::{DefineStream};
use liblink::define::{LinkDefine};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn call_function(&mut self, value: CallFunction) {
        /*
         * 找到定义, 依次读取定义位置的指令序列
         * 然后调用 self.execute
         * */
        let ld = self.link_define.clone();
        let ld = ld.as_ref::<LinkDefine>();
        match value.define_addr_ref() {
            FunctionAddress::Define(v) => {
                let iter = ld.read(v);
                for ins in iter {
                    self.execute(ins);
                }
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

