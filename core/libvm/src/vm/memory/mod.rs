use libtype::{AddressValue, AddressKey, AddressType};
use libtype::instruction::{DeleteData};
use crate::vm::VirtualMachine;

impl VirtualMachine {
    pub fn delete_data(&mut self, value: DeleteData) {
        let addr = value.fields_move();
        /*
         * TODO
         * */
    }
}

