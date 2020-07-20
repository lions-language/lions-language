use libgrammar::token::{TokenValue};
use crate::compile::{Compile, Compiler, ConstContext};

impl<F: Compile> Compiler<F> {
    pub fn const_number(&mut self, value: TokenValue) {
        let tt = value.token_type_clone();
        let t = self.tokentype_to_type(tt);
        let addr = self.static_addr_dispatch.alloc_static();
        let ad = addr.addr_ref().addr();
        self.value_buffer.push_with_addr(t, addr);
        let const_context = ConstContext::from_token_value(value, ad);
        self.cb.const_number(const_context);
    }
}

