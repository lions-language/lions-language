use libtype::instruction::{CallPrimevalFunction};
use libtype::function::{CallFunctionParamAddr};
use libtype::{Data, DataValue, AddressKey
    , AddressType, AddressValue};
use libtype::primeval::{PrimevalData, string::StrValue};
use crate::vm::VirtualMachine;
use std::io::{self, Write};

impl VirtualMachine {
    pub fn handle_println(&mut self, value: CallPrimevalFunction) {
        /*
        let param_addrs = value.param_addrs.expect("should not happend");
        let param_compile_addrs = match param_addrs.get(0).expect("should not happend") {
            CallFunctionParamAddr::Lengthen(ps) => {
                ps
            },
            _ => {
                panic!("should not happend");
            }
        };
        */
        /*
         * 获取参数
         *  println 一定是 1个变长参数 (Single(params))
         *  所以查找映射时, index: 0, offset 是 i(for i in 0..param_len)
         * */
        if value.call_param_len_clone() == 0 {
            return;
        }
        /*
         * 获取数据
         *  NOTE 的参数都是引用, 所以从 param_ref 中取数据
         * */
        let mut stdout = io::stdout();
        // for (index, param_compile_addr) in param_compile_addrs.iter().enumerate() {
        for i in 0..value.call_param_len_clone() {
            /*
            let param_compile_addr = AddressKey::new_with_all(0, 0, i, 0);
            let data_addr = self.thread_context.current_unchecked().get_data_addr_unchecked(
                &param_compile_addr);
            */
            /*
            let data_addr = self.thread_context.current_unchecked().get_param_ref_unchecked(i);
            // println!("{:?}", data_addr);
            let param_value = self.thread_context.current_unchecked().get_data_by_data_addr_unchecked(
                data_addr, &self.link_static);
            */
            /*
            let data = param_value.as_ref::<Data>();
            */
            /*
            self.thread_context.current_unchecked().print_current_addr_mapping();
            self.thread_context.current_unchecked().print_last_n_addr_mapping(1);
            self.thread_context.current_unchecked().print_last_n_addr_mapping(2);
            */
            let param_compile_addr = AddressValue::new(
                AddressType::AddrRef, AddressKey::new_with_all(0, 0, i, 0));
            let param_value = self.thread_context.current_unchecked().get_data_unchecked(
                &param_compile_addr, &self.link_static);
            let data = param_value.as_ref::<Data>();
            if i > 0 {
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

