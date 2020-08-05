use libtype::instruction::{CallPrimevalFunction};
use libtype::function::{CallFunctionParamAddr};
use libtype::{Data, DataValue};
use libtype::primeval::{PrimevalData, string::StrValue};
use crate::vm::VirtualMachine;
use std::io::{self, Write};

impl VirtualMachine {
    pub fn handle_println(&mut self, value: CallPrimevalFunction) {
        let param_addrs = value.param_addrs.expect("should not happend");
        let param_compile_addrs = match param_addrs.get(0).expect("should not happend") {
            CallFunctionParamAddr::Lengthen(ps) => {
                ps
            },
            _ => {
                panic!("should not happend");
            }
        };
        /*
         * 获取数据
         * */
        let mut stdout = io::stdout();
        for (index, param_compile_addr) in param_compile_addrs.iter().enumerate() {
            let param_value = self.thread_context.current_unchecked().get_data_unchecked(
                &param_compile_addr, &self.link_static);
            let data = param_value.as_ref::<Data>();
            if index > 0 {
                stdout.write(b" ");
            }
            match data.value_ref() {
                DataValue::Primeval(d) => {
                    match &d {
                        PrimevalData::Str(v) => {
                            match v.as_ref().expect("should not happend").value_ref() {
                                StrValue::Utf8(v) => {
                                    stdout.write(v.as_bytes());
                                },
                                StrValue::VecU8(v) => {
                                    stdout.write(v.as_slice());
                                }
                            }
                        },
                        _ => {
                            panic!("should not happend");
                        }
                    }
                },
                _ => {
                    panic!("should not happend");
                }
            }
        }
        stdout.write(b"\n");
        stdout.flush();
    }
}

