use libtype::instruction::{VariantValue};
use crate::vm::VirtualMachine;
use crate::data::Data;
use libcompile::address::AddressKey;

impl VirtualMachine {
    pub fn load_variant(&mut self, value: VariantValue) {
        let addr = self.memory_mut(&value.direction).alloc(Data::Address(value.direction));
        self.addr_mapping.bind(AddressKey::new_without_module(value.addr), addr);
    }
}

