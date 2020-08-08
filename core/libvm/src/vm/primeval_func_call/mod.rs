use libtype::instruction::{CallPrimevalFunction};
use libcommon::optcode::{OptCode};
use crate::vm::VirtualMachine;

/*
 * TODO: 使用宏循环, 提供一个变长参数, 得到嵌套的类型
 * */
macro_rules! extract_primeval_number_ref {
    ($data_ptr:expr, $typ:ident) => {{
        let data = $data_ptr.as_ref::<Data>();
        match data.value_ref() {
            DataValue::Primeval(d) => {
                match &d {
                    PrimevalData::$typ(v) => {
                        /*
                         * clone: 数值拷贝 (可以忽略效率)
                         * */
                        v.as_ref().expect("should not happend").to_std_ref().clone()
                    },
                    _ => {
                        unimplemented!("extract primeval data: {:?}", data.value_ref());
                    }
                }
            },
            _ => {
                panic!("expect extract primevate data, but meet {:?}", data.value_ref());
            }
        }
    }};
}

macro_rules! extract_primeval_utf8_str_ref {
    ($data_ptr:expr, $typ:ident) => {{
        let data = $data_ptr.as_ref::<Data>();
        match data.value_ref() {
            DataValue::Primeval(d) => {
                match &d {
                    PrimevalData::Str(v) => {
                        v.as_ref().expect("should not happend").extract_utf8_ref()
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
            OptCode::MoveUint16PlusOperatorRefUint8 => {
                self.move_uint16_plus_operator_ref_uint8(value);
            },
            OptCode::Println => {
                self.handle_println(value);
            },
            OptCode::RefUint8ToStr => {
                self.ref_uint8_to_str(value);
            },
            OptCode::MoveUint16ToStr => {
                self.move_uint16_to_str(value);
            },
            _ => {
                unimplemented!("{:?}", &value.opt);
            }
        }
    }
}

mod uint8;
mod uint16;
mod print;

