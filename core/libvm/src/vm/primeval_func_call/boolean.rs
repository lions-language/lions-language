use libtype::{Data, DataValue
    , AddressValue, AddressKey
    , AddressType};
use libtype::primeval::{PrimevalData};
use libtype::primeval::number::
    {uint8::Uint8, uint16::Uint16};
use libtype::primeval::string::{Str, StrValue};
use libtype::primeval::boolean::{Boolean, BooleanValue};
use libtype::instruction::{CallPrimevalFunction};
use libtype::function::{CallFunctionParamAddr};
use crate::vm::{VirtualMachine, AddressControl};
use crate::memory::{MemoryValue, Rand};
use crate::memory::stack;
use libcommon::ptr::{RefPtr};

impl VirtualMachine {
    pub fn ref_boolean_to_str(&mut self, value: CallPrimevalFunction) {
        let param_compile_addr = AddressValue::new(
            AddressType::AddrRef, AddressKey::new_with_all(0, 0, 0, 0, 0));
        let param_value = self.thread_context.current_unchecked().get_data_unchecked(
            &param_compile_addr, &self.link_static);
        let param_value = extract_primeval_boolean_ref!(param_value, Boolean);
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

    pub fn move_boolean_to_str(&mut self, value: CallPrimevalFunction) {
        let param_compile_addr = AddressValue::new(
            AddressType::Stack, AddressKey::new_with_all(0, 0, 0, 0, 0));
        let param_value = self.thread_context.current_unchecked().get_data_unchecked(
            &param_compile_addr, &self.link_static);
        let param_value = extract_primeval_boolean_ref!(param_value, Boolean);
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

