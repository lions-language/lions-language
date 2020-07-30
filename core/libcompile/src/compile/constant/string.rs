use libgrammar::token::{TokenValue};
use libtype::{AddressValue, AddressType};
use libtype::package::PackageStr;
use crate::compile::{Compile, Compiler, StaticContext
    , TokenValueExpand};
use crate::address::Address;

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn handle_const_string(&mut self, value: TokenValue) {
        /*
         * TokenType 转换为 Type
         * */
        let typ = self.consttoken_to_type(&value).clone();
        let addr = self.static_variant_dispatch.alloc(value.to_data());
        self.value_buffer.push_with_addr(typ.clone()
            , Address::new(AddressValue::new(AddressType::Static, addr.clone())));
        let const_context = StaticContext::from_token_value(
            PackageStr::Itself, typ, addr);
        self.cb.const_string(const_context);
    }
}

