use libgrammar::token::{TokenValue};
use libtype::package::PackageStr;
use crate::compile::{Compile, Compiler
    , StaticContext, TokenValueExpand};

impl<'a, F: Compile> Compiler<'a, F> {
    pub fn const_number(&mut self, value: TokenValue) {
        let tt = value.to_type();
        let addr = self.static_addr_dispatch.alloc_static();
        let ad = addr.addr_ref().addr_clone();
        self.value_buffer.push_with_addr(tt.clone(), addr);
        let const_context = StaticContext::from_token_value(
            PackageStr::Itself, tt, ad);
        self.cb.const_number(const_context);
    }
}

