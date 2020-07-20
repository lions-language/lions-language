use libtype::instruction::{VariantValue, AddressValue, AddressKey, AddressType};
use crate::vm::VirtualMachine;
use crate::data::Data;

impl VirtualMachine {
    pub fn load_variant(&mut self, value: VariantValue) {
        self.calc_stack.push(value.direction);
        /*
        match value.direction.typ_ref() {
            AddressType::Calc => {
                self.calc_stack.push(value.direction);
            },
            _ => {
                /*
                let addr = self.memory_mut(&value.direction).alloc(Data::Address(value.direction));
                self.addr_mapping.bind(AddressKey::new_without_module(value.addr), addr);
                */
                unimplemented!("{:?}", value.direction.typ_ref());
            }
        }
        */
    }
}

