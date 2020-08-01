use libtype::{Data, DataValue};
use libtype::primeval::{PrimevalData};
use libtype::primeval::number::
    {uint8::Uint8, uint16::Uint16};
use libtype::instruction::{CallPrimevalFunction};
use crate::vm::{VirtualMachine, AddressControl};
use crate::memory::{MemoryValue, Rand};
use crate::memory::stack;
use libcommon::ptr::{RefPtr};

impl VirtualMachine {
    pub fn ref_uint8_plus_operator_ref_uint8(&mut self, value: CallPrimevalFunction) {
        /*
         * 加载参数
         * TODO
         * 1. value.param_addrs 中存储的是上一个作用域中的地址索引
         *  需要从上一个作用域中的找到实际地址
         * */
        let left_compile_addr = self.calc_stack.pop_uncheck();
        let right_compile_addr = self.calc_stack.pop_uncheck();
        /*
         * 获取数据
         * */
        let left_value = left_compile_addr.get_data_unchecked(&self.memory_context
            , &self.link_static);
        let right_value = right_compile_addr.get_data_unchecked(&self.memory_context
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

