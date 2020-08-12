use libtype::{Data, DataValue};
use libtype::primeval::{PrimevalData};
use libtype::primeval::string::{Str, StrValue};
use libtype::instruction::{CallPrimevalFunction};
use libtype::function::{CallFunctionParamAddr};
use crate::vm::{VirtualMachine};

impl VirtualMachine {
    pub fn ref_str_plus_operator_ref_str(&mut self, value: CallPrimevalFunction) {
        /*
         * 加载参数
         *  在进入这里的时候, 当前作用域中的映射集合中已经存在了参数的映射
         *  所以, 直接用 索引0访问查找第一个参数的数据, 以此类推 注意:
         *  与自定义函数不同, 这里不需要为函数调用开辟新的作用域, 因为原生函数调用是 "死代码"
         * */
        let param_addrs = value.param_addrs.expect("should not happend");
        let left_param_compile_addr = match param_addrs.get(0).expect("should not happend") {
            CallFunctionParamAddr::Fixed(p) => {
                p
            },
            _ => {
                panic!("should not happend");
            }
        };
        let right_param_compile_addr = match param_addrs.get(1).expect("should not happend") {
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
        let left_value = self.thread_context.current_unchecked().get_data_unchecked(
            &left_param_compile_addr, &self.link_static);
        let right_value = self.thread_context.current_unchecked().get_data_unchecked(
            &right_param_compile_addr, &self.link_static);
        let left_value = extract_primeval_utf8_str_ref!(left_value, Str);
        let right_value = extract_primeval_utf8_str_ref!(right_value, Str);
        /*
         * 计算返回值
         * */
        let mut result = String::from(left_value);
        result.push_str(right_value);
        // println!("result: {}", result);
        /*
         * 检测返回值是否有效
         * */
        if !*value.return_data.is_alloc_ref() {
            return;
        }
        /*
         * 返回值需要分配内存 => 将返回值写入到内存
         * */
        self.thread_context.current_mut_unchecked().alloc_and_write_data(
            &value.return_data.addr_value()
            , Data::new(DataValue::Primeval(
                    PrimevalData::Str(
                        Some(Str::new(StrValue::Utf8(result)))))));
    }
}

