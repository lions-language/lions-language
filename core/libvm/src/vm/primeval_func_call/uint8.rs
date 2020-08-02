use libtype::{Data, DataValue};
use libtype::primeval::{PrimevalData};
use libtype::primeval::number::
    {uint8::Uint8, uint16::Uint16};
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
         *  所以, 直接用 索引0访问查找第一个参数的数据, 以此类推
         * 注意:
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
        let left_value = left_param_compile_addr.get_data_unchecked(&self.memory_context
            , &self.link_static);
        let right_value = right_param_compile_addr.get_data_unchecked(&self.memory_context
            , &self.link_static);
        let left_value = extract_data_ref!(left_value, Uint8);
        let right_value = extract_data_ref!(right_value, Uint8);
        /*
         * 计算返回值
         * */
        let result = left_value as u16 +
            right_value as u16;
        println!("{}", result);
        /*
         * 检测返回值是否有效
         * */
        if value.return_addr.is_invalid() {
            return;
        }
        /*
         * 返回值有效 => 将返回值写入到内存
         * */
        value.return_addr.alloc_and_write_data(
            Data::new(DataValue::Primeval(
                    PrimevalData::Uint16(
                        Some(Uint16::new(result)))))
            , &mut self.memory_context);
    }
}

