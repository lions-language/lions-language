use libtype::instruction::{VariantValue, AddressValue};
use crate::vm::VirtualMachine;
use crate::data::Data;
use libcompile::address::AddressKey;

impl VirtualMachine {
    pub fn load_variant(&mut self, value: VariantValue) {
        match &value.addr {
            AddressValue::Calc(_) => {
                self.calc_stack.push(value.direction);
            },
            _ => {
                /*
                let addr = self.memory_mut(&value.direction).alloc(Data::Address(value.direction));
                self.addr_mapping.bind(AddressKey::new_without_module(value.addr), addr);
                */
                unimplemented!();
            }
        }
    }
}

