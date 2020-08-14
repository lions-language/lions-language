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

macro_rules! extract_primeval_str_ref {
    ($data_ptr:expr, $typ:ident, $func:ident) => {{
        let data = $data_ptr.as_ref::<Data>();
        match data.value_ref() {
            DataValue::Primeval(d) => {
                match d {
                    PrimevalData::Str(v) => {
                        v.as_ref().expect("should not happend").$func()
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

macro_rules! extract_primeval_str_mut {
    ($data_ptr:expr, $typ:ident, $func:ident) => {{
        let data = $data_ptr.as_mut::<Data>();
        match data.value_mut() {
            DataValue::Primeval(d) => {
                match d {
                    PrimevalData::Str(v) => {
                        v.as_mut().expect("should not happend").$func()
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

macro_rules! extract_primeval_str_move {
    ($data:expr, $typ:ident, $func:ident) => {{
        match $data.value() {
            DataValue::Primeval(d) => {
                match d {
                    PrimevalData::Str(v) => {
                        v.expect("should not happend").$func()
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

macro_rules! extract_primeval_utf8_str_ref {
    ($data_ptr:expr, $typ:ident) => {{
        extract_primeval_str_ref!($data_ptr, $typ, extract_utf8_ref)
    }};
}

macro_rules! extract_primeval_utf8_str_mut {
    ($data_ptr:expr, $typ:ident) => {{
        extract_primeval_str_mut!($data_ptr, $typ, extract_utf8_mut)
    }};
}

macro_rules! extract_primeval_utf8_str_move {
    ($data:expr, $typ:ident) => {{
        extract_primeval_str_move!($data, $typ, extract_utf8)
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
            OptCode::RefStrPlusOperatorRefStr => {
                self.ref_str_plus_operator_ref_str(value);
            },
            OptCode::CreateRefStrPlusOperatorRefStr => {
                self.create_ref_str_plus_operator_ref_str(value);
            },
            OptCode::MutRefStrPlusOperatorRefStr => {
                self.mut_ref_str_plus_operator_ref_str(value);
            },
            OptCode::MutRefStrPlusOperatorMoveStr => {
                self.mut_ref_str_plus_operator_move_str(value);
            },
            _ => {
                unimplemented!("{:?}", &value.opt);
            }
        }
    }
}

mod uint8;
mod uint16;
mod string;
mod print;

