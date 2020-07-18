use libcompile::address::AddressKey;
use libtype::instruction::{CallPrimevalFunction, AddressValue};
use crate::vm::VirtualMachine;
use crate::memory::{MemoryValue, Rand};
use crate::memory::stack;
use crate::data::Data;
use libcommon::ptr::{RefPtr};

impl VirtualMachine {
    pub fn ref_uint8_plus_operator_ref_uint8(&mut self, value: CallPrimevalFunction) {
        /*
         * 加载参数
         * */
        let left = self.calc_stack.pop_uncheck();
        let right = self.calc_stack.pop_uncheck();
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
    }
}

