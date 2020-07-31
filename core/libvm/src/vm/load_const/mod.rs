use libtype::instruction::*;
use libtype::{AddressType, AddressValue};
use crate::memory::{Rand};
use crate::vm::{VirtualMachine};
use crate::data::Data;

/*
macro_rules! load_const {
    ($typ:ident, $self:ident, $value:ident) => {
        /*
         * 在静态区分配一个地址, 并与编译器传来的地址进行绑定
         * */
        let addr = $self.memory_context.static_stack.alloc(Data::$typ($value.value));
        $self.memory_context.static_addr_mapping.bind($value.addr.clone()
            , addr);
    }
}
*/

impl VirtualMachine {
    pub fn load_const_uint8(&mut self, value: Uint8Static) {
        // load_const!(Uint8, self, value);
    }

    pub fn load_const_uint16(&mut self, value: Uint16Static) {
        // load_const!(Uint16, self, value);
    }

    pub fn load_const_uint32(&mut self, value: Uint32Static) {
        // load_const!(Uint32, self, value);
    }

    pub fn load_const_string(&mut self, value: StringStatic) {
        // load_const!(Str, self, value);
    }

    pub fn read_static_variant(&mut self, value: StaticVariant) {
        /*
         * 加载到计算栈中
         * */
        self.calc_stack.push(AddressValue::new(
                AddressType::Static, value.addr_clone()));
    }
}

