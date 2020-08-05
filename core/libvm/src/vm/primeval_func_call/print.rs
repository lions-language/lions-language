use libtype::instruction::{CallPrimevalFunction};
use libtype::function::{CallFunctionParamAddr};
use libtype::{Data, DataValue};
use libtype::primeval::{PrimevalData};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn handle_println(&mut self, value: CallPrimevalFunction) {
        let param_addrs = value.param_addrs.expect("should not happend");
        let param_compile_addr = match param_addrs.get(0).expect("should not happend") {
            CallFunctionParamAddr::Fixed(p) => {
                p
            },
            _ => {
                panic!("should not happend");
            }
        };
        /*
         * 获取数据
         * */
        let param_value = self.thread_context.current_unchecked().get_data_unchecked(
            &param_compile_addr, &self.link_static);
        let param_value = extract_primeval_str_ref!(param_value, Str);
        println!("{:?}", param_value);
    }
}

