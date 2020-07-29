use libgrammar::token::{TokenValue};
use libtype::{AddressValue, AddressType};
use crate::compile::{Compile, Compiler, ConstContext};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_const_string(&mut self, value: TokenValue) {
        /*
         * TokenType 转换为 Type
         * */
        let typ = self.consttoken_to_type(&value);
        let addr = self.static_variant_dispatch.alloc();
        self.value_buffer.push_with_addr(typ
            , Address::new(AddressValue::new(AddressType::Static, addr.clone())));
        let const_context = ConstContext::from_token_value(value, addr);
        self.cb.const_string(const_context);
    }
}

