use libtype::instruction::{CallPrimevalFunction};
use libcommon::optcode::{OptCode};
use crate::vm::VirtualMachine;

macro_rules! extract_data_ref {
    ($data_ptr:expr, $typ:ident) => {{
        let data = $data_ptr.as_ref::<Data>();
        match data.value_ref() {
            DataValue::Primeval(d) => {
                match &d {
                    PrimevalData::Uint8(v) => {
                        /*
                         * clone: 数值拷贝 (可以忽略效率)
                         * */
                        v.as_ref().expect("should not happend").to_std_ref().clone()
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            },
            _ => {
                unimplemented!();
            }
        }
    }};
}

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

