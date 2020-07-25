use libgrammar::token::{TokenValue, TokenData};
use crate::compile::{Compile, Compiler, FunctionNamedStmtContext};

impl<F: Compile> Compiler<F> {
    pub fn handle_function_named_stmt(&mut self, value: TokenValue) {
        let s = match value.token_data.expect("should not happend") {
            TokenData::Id(v) => {
                v
            },
            _ => {
                panic!("should not happend");
            }
        };
        self.cb.function_named_stmt(FunctionNamedStmtContext{
            name: s
        });
    }
}
