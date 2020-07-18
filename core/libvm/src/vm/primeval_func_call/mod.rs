use libtype::instruction::{CallPrimevalFunction};
use libcommon::optcode::{OptCode};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn call_primeval_function(&mut self, value: CallPrimevalFunction) {
        match &value.opt {
            OptCode::RefUint8PlusOperatorRefUint8 => {
                self.ref_uint8_plus_operator_ref_uint8(value);
            },
            _ => {
                unimplemented!("{:?}", &value.opt);
            }
        }
    }
}

mod uint8;

