use libtype::{Data, DataValue
    , AddressValue, AddressKey
    , AddressType};
use libtype::primeval::{PrimevalData};
use libtype::primeval::number::
    {uint8::Uint8, uint16::Uint16};
use libtype::primeval::string::{Str, StrValue};
use libtype::instruction::{CallPrimevalFunction};
use libtype::function::{CallFunctionParamAddr};
use crate::vm::{VirtualMachine, AddressControl};
use crate::memory::{MemoryValue, Rand};
use crate::memory::stack;
use libcommon::ptr::{RefPtr};

impl VirtualMachine {
    pub fn ref_uint8_plus_operator_ref_uint8(&mut self, value: CallPrimevalFunction) {
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
        let left_value = extract_primeval_number_ref!(left_value, Uint8);
        let right_value = extract_primeval_number_ref!(right_value, Uint8);
        /*
         * 计算返回值
         * */
        let result = left_value as u16 +
            right_value as u16;
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
        /*
        self.thread_context.current_mut_unchecked().print_current_addr_mapping();
        self.thread_context.current_mut_unchecked().print_last_n_addr_mapping(1);
        self.thread_context.current_mut_unchecked().print_stack_datas();
        println!("{:?}", value.return_data.addr_value_ref());
        */
        self.thread_context.current_mut_unchecked().alloc_and_write_data(
            &value.return_data.addr_value()
            , Data::new(DataValue::Primeval(
                    PrimevalData::Uint16(
                        Some(Uint16::new(result))))));
        /*
        self.thread_context.current_mut_unchecked().print_current_addr_mapping();
        self.thread_context.current_mut_unchecked().print_last_n_addr_mapping(1);
        self.thread_context.current_mut_unchecked().print_stack_datas();
        */
    }

    pub fn ref_uint8_to_str(&mut self, value: CallPrimevalFunction) {
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
        // println!("{:?}", param_compile_addr);
        /*
        let param_value = self.thread_context.current_unchecked().get_data_unchecked(
            &param_compile_addr, &self.link_static);
        */
        // println!("get param ref");
        // self.thread_context.current_unchecked().
        /*
        let data_addr = self.thread_context.current_unchecked().get_param_ref_unchecked(0);
        let param_value = self.thread_context.current_unchecked().get_data_by_data_addr_unchecked(
            data_addr, &self.link_static);
        */
        let param_compile_addr = AddressValue::new(
            AddressType::AddrRef, AddressKey::new_with_all(0, 0, 0, 0, 0));
        let param_value = self.thread_context.current_unchecked().get_data_unchecked(
            &param_compile_addr, &self.link_static);
        let param_value = extract_primeval_number_ref!(param_value, Uint8);
        /*
         * 计算返回值
         * */
        let result = param_value.to_string();
        /*
         * 检测返回值是否有效
         * */
        if !*value.return_data.is_alloc_ref() {
            return;
        }
        /*
         * 返回值有效 => 将返回值写入到内存
         * 注意: 返回值一定要写入到前一个作用域中
         * */
        self.thread_context.current_mut_unchecked().alloc_and_write_data(
            &value.return_data.addr_value()
            , Data::new(DataValue::Primeval(
                    PrimevalData::Str(
                        Some(Str::new(StrValue::Utf8(result)))))));
        // self.thread_context.current_unchecked().print_stack_datas();
    }
}

