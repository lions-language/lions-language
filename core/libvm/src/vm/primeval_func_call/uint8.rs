use libtype::{AddressValue};
use libtype::instruction::{CallPrimevalFunction};
use crate::vm::{VirtualMachine, AddressControl};
use crate::memory::{MemoryValue, Rand};
use crate::memory::stack;
use crate::data::Data;
use libcommon::ptr::{RefPtr};

macro_rules! extract_data_ref {
    ($data_ref:expr, $typ:ident) => {
        if let Data::$typ(d) = $data_ref {
            d
        } else {
            panic!("should not happend");
        }
    };
}

impl VirtualMachine {
    pub fn ref_uint8_plus_operator_ref_uint8(&mut self, value: CallPrimevalFunction) {
        /*
         * 加载参数
         * */
        let left_compile_addr = self.calc_stack.pop_uncheck();
        let right_compile_addr = self.calc_stack.pop_uncheck();
        /*
         * 获取数据
         * */
        let left_value = left_compile_addr.get_data_unchecked(&self.memory_context);
        let right_value = right_compile_addr.get_data_unchecked(&self.memory_context);
        let left_value = extract_data_ref!(left_value.as_ref::<Data>(), Uint8);
        let right_value = extract_data_ref!(right_value.as_ref::<Data>(), Uint8);
        /*
         * 计算返回值
         * */
        let result = *left_value as u16 + *right_value as u16;
        /*
         * 将返回值写入到内存
         * */
        value.return_addr.alloc_and_write_data(
            Data::Uint16(result)
            , &mut self.memory_context);
        /*
        /*
         * 将编译期的地址转换为运行时的地址
         * */
        let mut left_addr = 0 as usize;
        let mut right_addr = 0 as usize;
        {
            left_addr = match &left {
                AddressValue::Static(a)
                | AddressValue::Stack(a) => {
                    self.addr_mapping.get_unwrap(&AddressKey::new_without_module(*a)).get()
                },
                _ => {
                    unimplemented!();
                }
            };
            right_addr = match &right {
                AddressValue::Static(a)
                | AddressValue::Stack(a) => {
                    self.addr_mapping.get_unwrap(&AddressKey::new_without_module(*a)).get()
                },
                _ => {
                    unimplemented!();
                }
            };
        }
        /*
         * 从地址中取值
         * */
        let left_value = match &left {
            AddressValue::Static(a) => {
                RefPtr::from_ref::<Data>(self.static_stack.get_unwrap(&MemoryValue::new(left_addr)))
            },
            AddressValue::Stack(a) => {
                RefPtr::from_ref::<Data>(self.thread_stack.get_unwrap(&MemoryValue::new(left_addr)))
            },
            _ => {
                unimplemented!();
            }
        };
        let right_value = match &right {
            AddressValue::Static(a) => {
                RefPtr::from_ref::<Data>(self.static_stack.get_unwrap(&MemoryValue::new(right_addr)))
            },
            AddressValue::Stack(a) => {
                RefPtr::from_ref::<Data>(self.thread_stack.get_unwrap(&MemoryValue::new(right_addr)))
            },
            _ => {
                unimplemented!();
            }
        };
        // let a = RefPtr::from_ref::<stack::RandStack>(self.memory_mut(&left));
        println!("{:?}, {:?}", left_value.as_ref::<Data>(), right_value.as_ref::<Data>());
        */
    }
}

