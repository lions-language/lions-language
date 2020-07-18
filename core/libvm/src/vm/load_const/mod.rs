use libtype::instruction::*;
use libcompile::address::AddressKey;
use crate::memory::{Rand};
use crate::vm::{VirtualMachine};
use crate::data::Data;

macro_rules! load_const {
    ($typ:ident, $self:ident, $value:ident) => {
        /*
         * 在静态区分配一个地址, 并与编译器传来的地址进行绑定
         * */
        let addr = $self.static_stack.alloc(Data::$typ($value.value));
        $self.addr_mapping.bind(AddressKey::new_without_module($value.addr)
            , addr);
    }
}

impl VirtualMachine {
    pub fn load_const_uint8(&mut self, value: Uint8Static) {
        load_const!(Uint8, self, value);
    }

    pub fn load_const_uint16(&mut self, value: Uint16Static) {
        load_const!(Uint16, self, value);
    }

    pub fn load_const_uint32(&mut self, value: Uint32Static) {
        load_const!(Uint32, self, value);
    }
}

