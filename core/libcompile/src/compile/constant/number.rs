use libgrammar::grammar::Grammar;
use libgrammar::token::{TokenValue};
use crate::compile::{Compile, Compiler, ConstContext};

impl<F: Compile> Compiler<F> {
    pub fn const_number(&mut self, value: TokenValue) {
        let tt = value.token_type_clone();
        let t = self.tokentype_to_type(tt);
        self.value_buffer.push(t);
        let const_context = ConstContext::from_token_value(value);
        self.cb.const_number(const_context);
    }
}

